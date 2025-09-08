"""
Tenant Analytics Service
Handles request logging and usage analytics per tenant
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta, date
from sqlalchemy.orm import Session
from sqlalchemy import and_, func

from app.models.tenant import TenantRequest, TenantUsageDaily


class TenantAnalyticsService:
    """Service for tenant-specific analytics and request logging"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def log_request(
        self,
        tenant_id: str,
        request_id: str,
        text_length: int,
        result: Dict[str, Any],
        processing_time_ms: float,
        cache_hit: bool = False,
        text_hash: str = None,
        user_agent: str = None,
        ip_address: str = None
    ) -> bool:
        """
        Log individual request for detailed analytics
        Also triggers daily usage update
        """
        try:
            # Create request log entry
            request_log = TenantRequest(
                tenant_id=tenant_id,
                request_id=request_id,
                text_length=text_length,
                text_hash=text_hash,
                is_malicious=result.get('is_malicious', False),
                confidence=result.get('confidence', 0.0),
                threat_types=result.get('threat_types', []),
                processing_time_ms=processing_time_ms,
                cache_hit=cache_hit,
                model_used=result.get('model_used'),
                user_agent=user_agent,
                ip_address=ip_address
            )
            
            self.db.add(request_log)
            self.db.commit()
            
            return True
            
        except Exception as e:
            self.db.rollback()
            # Log error but don't fail the request
            print(f"Failed to log request analytics: {e}")
            return False
    
    async def get_recent_stats(self, tenant_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get recent activity statistics for tenant"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Get recent requests
            recent_requests = self.db.query(TenantRequest).filter(
                and_(
                    TenantRequest.tenant_id == tenant_id,
                    TenantRequest.created_at >= cutoff_time
                )
            ).all()
            
            if not recent_requests:
                return self._empty_stats(hours)
            
            # Calculate statistics
            total_requests = len(recent_requests)
            malicious_count = sum(1 for r in recent_requests if r.is_malicious)
            safe_count = total_requests - malicious_count
            cache_hits = sum(1 for r in recent_requests if r.cache_hit)
            
            # Processing time statistics
            processing_times = [float(r.processing_time_ms) for r in recent_requests]
            avg_processing_time = sum(processing_times) / len(processing_times)
            min_processing_time = min(processing_times)
            max_processing_time = max(processing_times)
            
            # Confidence statistics (for malicious detections)
            malicious_requests = [r for r in recent_requests if r.is_malicious]
            avg_confidence = 0
            if malicious_requests:
                confidences = [float(r.confidence) for r in malicious_requests]
                avg_confidence = sum(confidences) / len(confidences)
            
            # Threat type analysis
            threat_type_counts = {}
            for request in malicious_requests:
                for threat_type in request.threat_types:
                    threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
            
            return {
                "period_hours": hours,
                "total_requests": total_requests,
                "malicious_blocked": malicious_count,
                "safe_allowed": safe_count,
                "block_rate_percentage": round((malicious_count / total_requests) * 100, 2),
                "cache_hits": cache_hits,
                "cache_hit_rate_percentage": round((cache_hits / total_requests) * 100, 2),
                "performance": {
                    "avg_processing_time_ms": round(avg_processing_time, 2),
                    "min_processing_time_ms": round(min_processing_time, 2),
                    "max_processing_time_ms": round(max_processing_time, 2)
                },
                "threat_analysis": {
                    "avg_confidence": round(avg_confidence, 3),
                    "threat_type_distribution": threat_type_counts
                },
                "timeline": self._get_hourly_breakdown(recent_requests, hours)
            }
            
        except Exception as e:
            print(f"Failed to get recent stats: {e}")
            return self._empty_stats(hours)
    
    def _empty_stats(self, hours: int) -> Dict[str, Any]:
        """Return empty statistics structure"""
        return {
            "period_hours": hours,
            "total_requests": 0,
            "malicious_blocked": 0,
            "safe_allowed": 0,
            "block_rate_percentage": 0,
            "cache_hits": 0,
            "cache_hit_rate_percentage": 0,
            "performance": {
                "avg_processing_time_ms": 0,
                "min_processing_time_ms": 0,
                "max_processing_time_ms": 0
            },
            "threat_analysis": {
                "avg_confidence": 0,
                "threat_type_distribution": {}
            },
            "timeline": []
        }
    
    def _get_hourly_breakdown(self, requests: list, hours: int) -> list:
        """Generate hourly breakdown of requests"""
        now = datetime.utcnow()
        hourly_data = {}
        
        # Initialize all hours with zero counts
        for i in range(hours):
            hour_start = now - timedelta(hours=i)
            hour_key = hour_start.strftime("%Y-%m-%d %H:00")
            hourly_data[hour_key] = {
                "hour": hour_key,
                "total": 0,
                "malicious": 0,
                "safe": 0,
                "cache_hits": 0
            }
        
        # Populate with actual data
        for request in requests:
            hour_key = request.created_at.strftime("%Y-%m-%d %H:00")
            if hour_key in hourly_data:
                hourly_data[hour_key]["total"] += 1
                if request.is_malicious:
                    hourly_data[hour_key]["malicious"] += 1
                else:
                    hourly_data[hour_key]["safe"] += 1
                if request.cache_hit:
                    hourly_data[hour_key]["cache_hits"] += 1
        
        # Return sorted by hour (most recent first)
        return sorted(hourly_data.values(), key=lambda x: x["hour"], reverse=True)
    
    async def get_daily_usage(self, tenant_id: str, days: int = 30) -> Dict[str, Any]:
        """Get daily usage summary for specified period"""
        try:
            end_date = date.today()
            start_date = end_date - timedelta(days=days)
            
            usage_records = self.db.query(TenantUsageDaily).filter(
                and_(
                    TenantUsageDaily.tenant_id == tenant_id,
                    TenantUsageDaily.date >= start_date,
                    TenantUsageDaily.date <= end_date
                )
            ).order_by(TenantUsageDaily.date.desc()).all()
            
            if not usage_records:
                return {
                    "period_days": days,
                    "total_requests": 0,
                    "total_blocked": 0,
                    "total_allowed": 0,
                    "avg_processing_time": 0,
                    "cache_hit_rate": 0,
                    "daily_data": []
                }
            
            # Calculate totals
            total_requests = sum(u.total_requests for u in usage_records)
            total_blocked = sum(u.malicious_blocked for u in usage_records)
            total_allowed = sum(u.safe_allowed for u in usage_records)
            total_cache_hits = sum(u.cache_hits for u in usage_records)
            total_cache_operations = total_cache_hits + sum(u.cache_misses for u in usage_records)
            
            # Weighted average processing time
            total_weighted_time = sum(
                float(u.avg_processing_time_ms) * u.total_requests 
                for u in usage_records
            )
            avg_processing_time = total_weighted_time / total_requests if total_requests > 0 else 0
            
            # Cache hit rate
            cache_hit_rate = (total_cache_hits / total_cache_operations * 100) if total_cache_operations > 0 else 0
            
            return {
                "period_days": days,
                "total_requests": total_requests,
                "total_blocked": total_blocked,
                "total_allowed": total_allowed,
                "block_rate_percentage": round((total_blocked / total_requests * 100), 2) if total_requests > 0 else 0,
                "avg_processing_time_ms": round(avg_processing_time, 2),
                "cache_hit_rate_percentage": round(cache_hit_rate, 2),
                "daily_data": [
                    {
                        "date": u.date.isoformat(),
                        "requests": u.total_requests,
                        "blocked": u.malicious_blocked,
                        "allowed": u.safe_allowed,
                        "avg_processing_ms": float(u.avg_processing_time_ms),
                        "cache_hits": u.cache_hits,
                        "cache_misses": u.cache_misses,
                        "estimated_cost": float(u.estimated_cost_usd)
                    } for u in usage_records
                ]
            }
            
        except Exception as e:
            print(f"Failed to get daily usage: {e}")
            return {"error": str(e)}
    
    async def get_threat_analysis(self, tenant_id: str, days: int = 7) -> Dict[str, Any]:
        """Get detailed threat analysis for tenant"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get malicious requests in period
            malicious_requests = self.db.query(TenantRequest).filter(
                and_(
                    TenantRequest.tenant_id == tenant_id,
                    TenantRequest.created_at >= cutoff_date,
                    TenantRequest.is_malicious == True
                )
            ).all()
            
            if not malicious_requests:
                return {
                    "period_days": days,
                    "total_threats": 0,
                    "threat_types": {},
                    "confidence_distribution": {},
                    "threat_timeline": []
                }
            
            # Analyze threat types
            threat_type_counts = {}
            confidence_buckets = {"low": 0, "medium": 0, "high": 0}
            
            for request in malicious_requests:
                # Count threat types
                for threat_type in request.threat_types:
                    threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
                
                # Bucket confidence levels
                confidence = float(request.confidence)
                if confidence < 0.5:
                    confidence_buckets["low"] += 1
                elif confidence < 0.8:
                    confidence_buckets["medium"] += 1
                else:
                    confidence_buckets["high"] += 1
            
            # Daily threat timeline
            daily_threats = {}
            for request in malicious_requests:
                day_key = request.created_at.date().isoformat()
                if day_key not in daily_threats:
                    daily_threats[day_key] = {
                        "date": day_key,
                        "count": 0,
                        "avg_confidence": 0,
                        "threat_types": set()
                    }
                
                daily_threats[day_key]["count"] += 1
                daily_threats[day_key]["threat_types"].update(request.threat_types)
            
            # Calculate average confidence per day
            for day_key, day_data in daily_threats.items():
                day_requests = [r for r in malicious_requests if r.created_at.date().isoformat() == day_key]
                if day_requests:
                    avg_conf = sum(float(r.confidence) for r in day_requests) / len(day_requests)
                    day_data["avg_confidence"] = round(avg_conf, 3)
                    day_data["threat_types"] = list(day_data["threat_types"])
            
            return {
                "period_days": days,
                "total_threats": len(malicious_requests),
                "threat_types": threat_type_counts,
                "confidence_distribution": confidence_buckets,
                "avg_confidence": round(
                    sum(float(r.confidence) for r in malicious_requests) / len(malicious_requests), 3
                ),
                "threat_timeline": sorted(daily_threats.values(), key=lambda x: x["date"], reverse=True)
            }
            
        except Exception as e:
            print(f"Failed to get threat analysis: {e}")
            return {"error": str(e)}