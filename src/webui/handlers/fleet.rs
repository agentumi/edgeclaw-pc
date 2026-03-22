use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use serde_json::json;
use tokio::net::TcpStream;

/// GET /api/v2.2/fleet/status
///
/// 에이전트 합대(Fleet)의 시각화 데이터를 제공하기 위한 통합 API입니다.
/// 미션 상태, 피어 연결 정보, AI 합의 상태, 블록체인 앵커링 현황을 포함합니다.
pub async fn handle_fleet_status(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // 1. Mission Registry 정보 추출
    let missions = {
        let ai = engine
            .ai_manager()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ai.mission_registry()
            .list()
            .into_iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "name": m.name,
                    "role": m.role,
                    "status": "active", // V2.2에서는 동적 상태 추적 기능 추가 예정
                })
            })
            .collect::<Vec<_>>()
    };

    // 2. Peer Manager 정보 추출 (Fleet Nodes)
    let peers = {
        let pm = engine
            .peer_manager()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pm.list_peers()
            .into_iter()
            .map(|p| {
                json!({
                    "peer_id": p.peer_id,
                    "name": p.device_name,
                    "type": p.device_type,
                    "connected": p.is_connected,
                    "role": p.role,
                })
            })
            .collect::<Vec<_>>()
    };

    // 3. Blockchain Anchor 정보 (Trust Status)
    let blockchain_status = {
        let bc = engine.blockchain_client();
        json!({
            "connected": bc.is_connected(),
            "last_anchor": bc.list_devices().last().map(|d| d.object_id.clone()), // 마지막 기록된 오브젝트 ID 참조
            "cache_size": bc.cache_size(),
        })
    };

    // 4. 통합 응답 생성
    let body = json!({
        "version": "2.2.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "fleet_nodes": peers,
        "active_missions": missions,
        "blockchain": blockchain_status,
        "intelligence": {
            "mode": engine.mode(),
            "last_consensuses": [], // 세션별 합의 히스토리 노출 가능 (추후 확장)
        }
    });

    let json_bytes = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json_bytes, cors_origin).await
}
