"""Main FastAPI application for SENTINEL vulnerability scanner."""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import logging

from backend.core.config import settings
from backend.core.database import get_db, init_db
from backend.scanner.engine import scanner_engine
from backend.scanner.base_module import ScanConfig, ScanType
from backend.api.models import Scan, ScanModule, ScanVulnerability
from sqlalchemy.orm import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="SENTINEL - Comprehensive Vulnerability Scanner API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Initialize database
    init_db()
    
    logger.info("Application startup complete")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    logger.info("Shutting down application")
    await scanner_engine.shutdown()

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat()
    }

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_scans": len(scanner_engine.active_scans),
        "modules_loaded": len(scanner_engine.modules)
    }

# Scanner modules endpoints
@app.get("/api/v1/modules")
async def get_modules():
    """Get available scanner modules."""
    return {
        "modules": scanner_engine.get_available_modules(),
        "total": len(scanner_engine.modules)
    }

@app.get("/api/v1/modules/{module_name}")
async def get_module_info(module_name: str):
    """Get information about a specific module."""
    if module_name not in scanner_engine.modules:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")
    
    module = scanner_engine.modules[module_name]
    return module.get_info()

# Scan management endpoints
@app.post("/api/v1/scans")
async def create_scan(
    background_tasks: BackgroundTasks,
    target: str = Body(..., description="Target URL or IP address"),
    modules: List[str] = Body(..., description="List of scanner modules to run"),
    scan_type: Optional[ScanType] = Body(ScanType.PASSIVE, description="Type of scan"),
    config: Optional[Dict[str, Any]] = Body(None, description="Additional scan configuration"),
    auth: Optional[Dict[str, Any]] = Body(None, description="Authentication credentials if needed"),
    metadata: Optional[Dict[str, Any]] = Body(None, description="Additional metadata"),
    db: Session = Depends(get_db)
):
    """Create and start a new scan."""
    
    # Validate request
    is_valid, errors = scanner_engine.validate_scan_request(target, modules, scan_type)
    if not is_valid:
        raise HTTPException(status_code=400, detail={"errors": errors})
    
    # Check consent for active scanning
    if scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE] and settings.require_consent:
        # In production, check consent database
        logger.warning(f"Active scan requested for {target} - consent verification required")
    
    # Create scan configuration
    scan_config = ScanConfig(
        target=target,
        scan_type=scan_type,
        timeout=config.get('timeout', settings.scan_timeout_seconds) if config else settings.scan_timeout_seconds,
        rate_limit=config.get('rate_limit', 10) if config else 10,
        max_depth=config.get('max_depth', 3) if config else 3,
        auth=auth,
        custom_params=config if config else {}
    )
    
    # Create scan job
    scan_job = await scanner_engine.create_scan(
        target=target,
        modules=modules,
        config=scan_config,
        metadata=metadata
    )
    
    # Save to database
    db_scan = Scan(
        id=scan_job.id,
        target=target,
        scan_type=scan_type,
        modules_requested=modules,
        config=config if config else {},
        metadata=metadata if metadata else {}
    )
    db.add(db_scan)
    db.commit()
    
    # Start scan in background
    background_tasks.add_task(execute_scan_task, scan_job.id, db)
    
    return {
        "scan_id": scan_job.id,
        "status": "created",
        "target": target,
        "modules": modules,
        "message": "Scan created and queued for execution"
    }

async def execute_scan_task(scan_id: str, db: Session):
    """Execute scan in background."""
    try:
        # Execute scan
        scan_job = await scanner_engine.execute_scan(scan_id)
        
        # Update database
        db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if db_scan:
            db_scan.status = scan_job.status
            db_scan.started_at = scan_job.started_at
            db_scan.completed_at = scan_job.completed_at
            db_scan.progress = scan_job.progress
            db_scan.errors = scan_job.errors
            
            # Update vulnerability counts
            db_scan.total_vulnerabilities = len(scan_job.vulnerabilities)
            
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in scan_job.vulnerabilities:
                severity_counts[vuln.severity.value] += 1
            
            db_scan.critical_count = severity_counts["critical"]
            db_scan.high_count = severity_counts["high"]
            db_scan.medium_count = severity_counts["medium"]
            db_scan.low_count = severity_counts["low"]
            db_scan.info_count = severity_counts["info"]
            
            # Save module results
            for module_name, result in scan_job.results.items():
                db_module = ScanModule(
                    scan_id=scan_id,
                    module_name=module_name,
                    started_at=result.started_at,
                    completed_at=result.completed_at,
                    success=result.success,
                    vulnerabilities_found=len(result.vulnerabilities),
                    errors=result.errors,
                    warnings=result.warnings,
                    info=result.info,
                    statistics=result.statistics
                )
                db.add(db_module)
            
            # Save vulnerabilities
            for vuln in scan_job.vulnerabilities:
                db_vuln = ScanVulnerability(
                    scan_id=scan_id,
                    module=vuln.module,
                    name=vuln.name,
                    description=vuln.description,
                    severity=vuln.severity,
                    confidence=vuln.confidence,
                    cvss_score=vuln.cvss_score,
                    cve_ids=vuln.cve_ids,
                    cwe_ids=vuln.cwe_ids,
                    affected_urls=vuln.affected_urls,
                    evidence=vuln.evidence,
                    remediation=vuln.remediation,
                    references=vuln.references,
                    metadata=vuln.metadata
                )
                db_vuln.calculate_risk_score()
                db.add(db_vuln)
            
            db.commit()
            
    except Exception as e:
        logger.error(f"Error executing scan {scan_id}: {str(e)}")
        
        # Update scan status to failed
        db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if db_scan:
            db_scan.status = "failed"
            db_scan.errors = [str(e)]
            db.commit()

@app.get("/api/v1/scans")
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[str] = Query(None),
    target: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List all scans with pagination."""
    query = db.query(Scan)
    
    if status:
        query = query.filter(Scan.status == status)
    if target:
        query = query.filter(Scan.target.contains(target))
    
    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "scans": [scan.to_dict() for scan in scans]
    }

@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get scan details."""
    # Check active scans first
    scan_job = scanner_engine.get_scan_status(scan_id)
    if scan_job and scan_job.status.value in ["pending", "running"]:
        return {
            "id": scan_job.id,
            "target": scan_job.target,
            "status": scan_job.status.value,
            "progress": scan_job.progress,
            "current_module": scan_job.current_module,
            "started_at": scan_job.started_at.isoformat() if scan_job.started_at else None,
            "modules": scan_job.modules
        }
    
    # Check database
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return db_scan.to_dict()

@app.get("/api/v1/scans/{scan_id}/results")
async def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    """Get detailed scan results."""
    # Check if scan is completed
    results = scanner_engine.get_scan_results(scan_id)
    if results:
        return results
    
    # Get from database
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if db_scan.status != "completed":
        raise HTTPException(status_code=400, detail=f"Scan is {db_scan.status}, not completed")
    
    # Get vulnerabilities
    vulnerabilities = db.query(ScanVulnerability).filter(
        ScanVulnerability.scan_id == scan_id
    ).all()
    
    # Get module results
    modules = db.query(ScanModule).filter(
        ScanModule.scan_id == scan_id
    ).all()
    
    return {
        "scan": db_scan.to_dict(),
        "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities],
        "modules": [module.to_dict() for module in modules]
    }

@app.get("/api/v1/scans/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Get vulnerabilities found in a scan."""
    query = db.query(ScanVulnerability).filter(ScanVulnerability.scan_id == scan_id)
    
    if severity:
        query = query.filter(ScanVulnerability.severity == severity)
    if module:
        query = query.filter(ScanVulnerability.module == module)
    
    total = query.count()
    vulnerabilities = query.order_by(
        ScanVulnerability.severity.desc(),
        ScanVulnerability.risk_score.desc()
    ).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities]
    }

@app.delete("/api/v1/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    success = await scanner_engine.cancel_scan(scan_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled or not found")
    
    return {"message": f"Scan {scan_id} cancelled successfully"}

# Active scans monitoring
@app.get("/api/v1/scans/active")
async def get_active_scans():
    """Get list of currently active scans."""
    return {
        "active_scans": scanner_engine.get_active_scans(),
        "total": len(scanner_engine.active_scans)
    }

# Scan history
@app.get("/api/v1/scans/history")
async def get_scan_history(limit: int = Query(10, ge=1, le=50)):
    """Get recent scan history."""
    return {
        "history": scanner_engine.get_scan_history(limit),
        "limit": limit
    }

# Vulnerability statistics
@app.get("/api/v1/stats/vulnerabilities")
async def get_vulnerability_stats(db: Session = Depends(get_db)):
    """Get vulnerability statistics."""
    from sqlalchemy import func
    
    # Total vulnerabilities by severity
    severity_stats = db.query(
        ScanVulnerability.severity,
        func.count(ScanVulnerability.id).label('count')
    ).group_by(ScanVulnerability.severity).all()
    
    # Top vulnerable modules
    module_stats = db.query(
        ScanVulnerability.module,
        func.count(ScanVulnerability.id).label('count')
    ).group_by(ScanVulnerability.module).order_by(
        func.count(ScanVulnerability.id).desc()
    ).limit(10).all()
    
    # Most common vulnerabilities
    common_vulns = db.query(
        ScanVulnerability.name,
        func.count(ScanVulnerability.id).label('count')
    ).group_by(ScanVulnerability.name).order_by(
        func.count(ScanVulnerability.id).desc()
    ).limit(10).all()
    
    return {
        "severity_distribution": {str(s): c for s, c in severity_stats},
        "top_modules": [{"module": m, "count": c} for m, c in module_stats],
        "common_vulnerabilities": [{"name": n, "count": c} for n, c in common_vulns]
    }

# Error handling
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
