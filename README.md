## 使用情況調查（2026-11-09）

> 本節為 hanlin-edu-tech repo 清理作業的調查紀錄，待負責人確認後決定封存或刪除。

- 調查結論：仍在使用
- 建議處置：保留，理由：正式環境運行中的 tutor-cashflow 直接依賴本 repo 發布的 `com.eHanlin.api:pay2go-crypto:1.0.0`，並經由 e-invoice-client 間接依賴。
- 最後更新：pushedAt 2021-06-18；最後 commit `5251f6a` 2021-06-18 AaronChuang [ch-947] 移植舊有lib至gcs上
- 用途：智付寶、智付通系列 API 的 AES 加解密與 SHA-256 檢查碼 Java 工具（`Pay2GoCrypto`），以 Gradle `maven-publish` 發布為 `com.eHanlin.api:pay2go-crypto:1.0.0` 到公司 GCS Maven 套件庫；本身無獨立部署。

### 檢查結果

| 檢查項目 | 結果 | 依據 |
|---|---|---|
| GitHub 活動 | 2021-06-18 後無 commit | 共 3 個 commit（2017-11-07～2021-06-18，Rodick.Huang 2、AaronChuang 1）；分支僅 `master`；tag 0、release 0；PR 0、issue 0；Actions workflow 0、執行紀錄 0；webhook 0；非 fork；無 Dockerfile、cloudbuild.yaml |
| org 內程式碼引用 | tutor-cashflow、e-invoice-client 依賴本 repo 1.0.0 | `gh search code --owner hanlin-edu-tech`：`pay2go-crypto` 除本 repo 外命中 e-invoice-client 與 tutor-cashflow（private）的 Gradle 依賴宣告；`Pay2GoCrypto` 除本 repo 外命中 e-invoice-client 的 `Pay2GoInvoice.java` 與 tutor-cashflow 的 4 支程式（金流設定、驗證服務、藍新金流 controller 與 provider）。tutor-cashflow 正式環境運行版本對應的原始碼同樣宣告此依賴，GCS 套件庫中 1.0.0 的 jar 於 2021-06-18 上傳。已查核，細節記錄於內部調查報告 |
| GCP 部署 | 本 repo 無部署；依賴方 tutor-cashflow 在正式環境運行中 | 19 個 GCP 專案的 Cloud Run、Cloud Functions、Cloud Build trigger、GCR、Artifact Registry、Cloud Scheduler、App Engine 清單與 8 個 GKE 叢集以 `pay2go`、`crypto` 搜尋 0 筆；依賴方部署已查核，細節記錄於內部調查報告 |
| AWS 部署 | 查無 | 4 個 AWS 帳號的 Lambda、API Gateway（REST 與 HTTP API）、CloudFront、ECR、ECS、EventBridge、SQS、S3 以 `pay2go`、`crypto` 搜尋 0 筆 |

### 待確認事項
- 無

# pay2go-crypto
智付寶、智付通、智付系列通用加解密工具
