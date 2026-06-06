# AEGIS NAS 배포 및 실제 디바이스 테스트 가이드

이 문서는 개발 완료된 AEGIS 보안 솔루션을 **연구실 NAS 서버(Spring Boot)** 및 **실제 안드로이드 스마트폰(APK)** 환경에 맞게 유연하게 설정하고 테스트하기 위한 가이드라인입니다.

---

## 1. 🖥️ 백엔드 (NAS & Docker) 설정 및 배포

### ① application.properties 외부화 설정
소스코드에 NAS IP나 포트, 데이터베이스 비밀번호를 하드코딩하지 않고, 환경변수로부터 주입받도록 구성합니다.
```properties
# aegis-backend/src/main/resources/application.properties
server.port=${SERVER_PORT:8080}
spring.data.mongodb.uri=${MONGODB_URI:mongodb://root:example@localhost:27017/forensic_db?authSource=admin}
```

### ② Docker Compose 배포 파일 예시
NAS 배포 시 소스코드 빌드 결과물(JAR)을 아래의 `docker-compose.yml` 및 `.env` 구성을 사용하여 안전하게 기동합니다.

* **`.env` 파일 설정 (NAS 전용 민감 정보 외부 관리)**:
  ```env
  SPRING_PROFILES_ACTIVE=prod
  SERVER_PORT=8443
  MONGODB_URI=mongodb://root:nas_secure_pass@nas-mongodb-container:27017/forensic_db?authSource=admin
  ```
* **`docker-compose.yml`**:
  ```yaml
  version: '3.8'
  services:
    aegis-backend:
      image: aegis-backend:latest
      ports:
        - "${SERVER_PORT}:${SERVER_PORT}"
      environment:
        - SPRING_PROFILES_ACTIVE=${SPRING_PROFILES_ACTIVE}
        - MONGODB_URI=${MONGODB_URI}
  ```

---

## 2. 📱 안드로이드 (실제 기기 APK) 설정 및 빌드

### ① 빌드 배리언트(Build Variants) 설정
연구실 NAS 서버 환경과 로컬 개발 환경의 서버 접속 주소를 분리하여 빌드할 수 있도록 Gradle 환경을 설정합니다.

* **`aegis/app/build.gradle.kts`**:
  ```kotlin
  android {
      ...
      buildFeatures {
          buildConfig = true
      }
      flavorDimensions.add("stage")
      productFlavors {
          create("localDev") {
              dimension = "stage"
              buildConfigField("String", "BASE_URL", "\"https://10.0.2.2:8080/\"")
          }
          create("labNas") {
              dimension = "stage"
              buildConfigField("String", "BASE_URL", "\"https://[연구실_NAS_IP]:[포트]/\"")
          }
      }
  }
  ```

### ② 소스코드 내 동적 서버 주소 바인딩
개발 코드 내에서 서버 API 주소 호출 시 `BuildConfig.BASE_URL`을 사용하도록 호출부를 단일화합니다.
```java
// ServerTransmitter.java
String baseUrl = BuildConfig.BASE_URL;
```

### ③ 사설 SSL 인증서 신뢰 설정 (network_security_config.xml)
실제 단말은 공인 CA가 서명하지 않은 사설 인증서(NAS 자체 서명 등)를 신뢰하지 않아 통신에 실패합니다. 연구실 테스트를 위해 `labNas`용 별도 네트워크 보안 설정을 마련합니다.

* **`src/labNas/res/xml/network_security_config.xml`**:
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <network-security-config>
      <domain-config cleartextTrafficPermitted="false">
          <domain includeSubdomains="true">연구실_NAS_도메인_또는_IP</domain>
          <trust-anchors>
              <!-- 연구실 NAS 루트 인증서 등록 -->
              <certificates src="@raw/lab_nas_ca" />
              <certificates src="system" />
          </trust-anchors>
      </domain-config>
  </network-security-config>
  ```

---

## ⚠️ 무결성 검증 주의사항
* **리포트 해시 검증**: 리포트 발행 이후 파일 해시 불일치가 발생할 경우 내용물 렌더링이 완전 차단됩니다. NAS 서버 파일 시스템 권한 및 DB의 해시 기록(SHA-256)이 외부 요인으로 변조되지 않도록 보호해야 합니다.
