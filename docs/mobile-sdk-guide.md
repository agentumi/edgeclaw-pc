# Mobile SDK Guide — UniFFI 바인딩 사용법

> EdgeClaw V4.0 — Android (Kotlin) / iOS (Swift) UniFFI 연동 가이드

## 개요

EdgeClaw Mobile은 **UniFFI** (Rust → Kotlin / Swift FFI)를 통해 Rust 코어 라이브러리를 모바일 앱에 직접 연동합니다. 네트워크 레이턴시 없이 암호화, 서명, 검색, 동기화를 로컬에서 수행합니다.

```
Android App (Kotlin + Compose)     iOS App (SwiftUI)
        ↓                                ↓
    JNI Bridge                     Swift Bindings
        ↓                                ↓
          Rust Core Library (edgeclaw-core)
          ├─ Identity (Ed25519/X25519)
          ├─ Session (AES-256-GCM)
          ├─ Policy (RBAC, 4 roles)
          ├─ Activity Log (search, stats)
          └─ ECNP Codec (Binary)
```

---

## 빌드 준비

### Rust 크로스 컴파일 설정

```bash
# Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# iOS targets (macOS only)
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

### Android 빌드

```bash
cd edgeclaw-core
cargo build --target aarch64-linux-android --release

# JNI 라이브러리 복사
cp target/aarch64-linux-android/release/libedgeclaw_core.so \
   ../android/app/src/main/jniLibs/arm64-v8a/
```

### iOS 빌드

```bash
cd edgeclaw-core
cargo build --target aarch64-apple-ios --release

# UniFFI Swift 바인딩 생성
cd ../ios
./generate-bindings.sh
```

---

## UniFFI 인터페이스 (edgeclaw.udl)

```webidl
namespace edgeclaw {
  // 생성 및 초기화
  EdgeClawEngine create_engine(string device_name);
};

interface EdgeClawEngine {
  // 활동 로그 조회
  sequence<ActivityEntry> query_team_activities(
    string project, string? since, u32 limit
  );

  // 세션 상세 조회
  AgentSession get_session_detail(string session_id);

  // 활동 통계
  ActivityStats get_activity_stats(string? project);

  // 전문 검색
  sequence<ActivityEntry> search_activities(string query, u32 limit);

  // Desktop 동기화 연결
  void connect_to_desktop(string host, u16 port);
  void disconnect_from_desktop();
  boolean is_connected();
};

dictionary ActivityEntry {
  string id;
  string session_id;
  string agent_id;
  string agent_name;
  string activity_type;
  string project;
  string? file_path;
  string content;
  sequence<string> tags;
  u8 importance;
  string timestamp;
  u64 lamport_clock;
  string hash;
};

dictionary AgentSession {
  string id;
  string agent_id;
  string agent_name;
  string project;
  string started_at;
  string? ended_at;
  string status;
  string? summary;
  f64 total_cost_usd;
};

dictionary ActivityStats {
  u64 total_entries;
  record<string, u64> by_type;
  record<string, u64> by_project;
  u64 total_tokens;
  f64 total_cost_usd;
};

dictionary ContextInjection {
  sequence<ActivityBrief> recent_summaries;
  sequence<ActivityBrief> important_activities;
  sequence<ActivityBrief> recent_errors;
  sequence<ActivityBrief> active_decisions;
  string? memory_md;
  sequence<RepeatedError> repeated_errors;
  sequence<string> cross_session_insights;
};
```

---

## Kotlin 사용법 (Android)

### 엔진 초기화

```kotlin
import com.edgeclaw.mobile.core.EdgeClawEngine

class EdgeClawApp : Application() {
    lateinit var engine: EdgeClawEngine

    override fun onCreate() {
        super.onCreate()
        engine = EdgeClawEngine.create("my-phone")
    }
}
```

### 활동 피드 조회

```kotlin
// ViewModel
class ActivityViewModel : ViewModel() {
    private val _activities = MutableStateFlow<List<ActivityEntry>>(emptyList())
    val activities: StateFlow<List<ActivityEntry>> = _activities

    fun loadActivities(project: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val entries = engine.queryTeamActivities(
                project = project,
                since = null,
                limit = 50u
            )
            _activities.value = entries
        }
    }

    fun search(query: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val results = engine.searchActivities(query, 20u)
            _activities.value = results
        }
    }
}
```

### Desktop 동기화

```kotlin
fun connectToDesktop(host: String, port: Int) {
    viewModelScope.launch(Dispatchers.IO) {
        try {
            engine.connectToDesktop(host, port.toUShort())
            // SyncActivityQuery/Response over ECNP
        } catch (e: Exception) {
            Log.e("EdgeClaw", "Desktop sync failed: ${e.message}")
        }
    }
}
```

### Compose UI 예시

```kotlin
@Composable
fun ActivityFeedScreen(viewModel: ActivityViewModel) {
    val activities by viewModel.activities.collectAsState()

    LazyColumn {
        items(activities) { entry ->
            ActivityCard(entry)
        }
    }
}

@Composable
fun ActivityCard(entry: ActivityEntry) {
    Card(modifier = Modifier.fillMaxWidth().padding(8.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = entry.content,
                style = MaterialTheme.typography.bodyMedium
            )
            Row(horizontalArrangement = Arrangement.SpaceBetween) {
                Text(entry.activityType, style = MaterialTheme.typography.labelSmall)
                Text(entry.timestamp, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
```

---

## Swift 사용법 (iOS)

### 엔진 초기화

```swift
import EdgeClawCore

@Observable
class AppState {
    let engine: EdgeClawEngine

    init() {
        engine = createEngine(deviceName: "my-iphone")
    }
}
```

### 활동 조회

```swift
@Observable
class ActivityStore {
    var activities: [ActivityEntry] = []
    private let engine: EdgeClawEngine

    func loadActivities(project: String) async {
        activities = try await Task.detached {
            self.engine.queryTeamActivities(
                project: project,
                since: nil,
                limit: 50
            )
        }.value
    }

    func search(query: String) async {
        activities = try await Task.detached {
            self.engine.searchActivities(query: query, limit: 20)
        }.value
    }
}
```

### SwiftUI View 예시

```swift
struct ActivityFeedView: View {
    @State private var store = ActivityStore()

    var body: some View {
        NavigationStack {
            List(store.activities, id: \.id) { entry in
                VStack(alignment: .leading) {
                    Text(entry.content)
                        .font(.body)
                    HStack {
                        Text(entry.activityType)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(entry.timestamp)
                            .font(.caption2)
                    }
                }
            }
            .navigationTitle("Activity Feed")
            .searchable(text: $searchQuery)
        }
    }
}
```

---

## Desktop 동기화 프로토콜

Mobile ↔ Desktop 동기화는 ECNP v1.1 바이너리 프로토콜을 사용합니다:

| 메시지 타입 | 코드 | 방향 | 설명 |
|-----------|------|------|------|
| `SyncActivityQuery`    | 0x30 | Mobile → Desktop | 활동 조회 요청 |
| `SyncActivityResponse` | 0x31 | Desktop → Mobile | 활동 데이터 응답 |
| `SyncSessionQuery`     | 0x32 | Mobile → Desktop | 세션 조회 요청 |
| `SyncSessionResponse`  | 0x33 | Desktop → Mobile | 세션 데이터 응답 |

모든 통신은 X25519 ECDH + AES-256-GCM으로 암호화됩니다.

---

## 테스트

```bash
# Rust 코어 테스트 (82개)
cd edgeclaw-core && cargo test

# UniFFI 바인딩 테스트 (9개)
cargo test uniffi_bridge::tests

# Android 테스트 (29개)
cd ../android && ./gradlew test

# ViewModel 테스트 (6개)
./gradlew test --tests com.edgeclaw.mobile.core.ActivityViewModelTest

# Repository 테스트 (4개)
./gradlew test --tests com.edgeclaw.mobile.core.ActivityRepositoryTest
```

---

## 제한 사항

- **오프라인 모드**: 로컬 Rust 코어만 사용 (Desktop 동기화 불가)
- **검색**: 모바일은 in-memory 검색 (Tantivy 미포함, 용량 제한)
- **AI 요약**: Desktop에서만 실행, 결과를 동기화로 수신
- **블록체인 앵커링**: Desktop 전용

---

> 참고: [iOS QuickStart](../../edgeclaw_mobile/ios/IOS_QUICKSTART.md) · [Activity Log API](activity-log-api-reference.md)
