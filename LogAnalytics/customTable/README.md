# Preparation of custom table for certLC statistics

1. create a new DCE in the same region as the Log Analytics workspace
2. fetch its ingestion URL
3. in LogAnalytics, create a new custom table, DCR-based, called **certlc**. Do not append _CL (it will be done automatically). When asked, create a DCR for the table in the same region
4. import the schema from the file `certlcstats-schema.json`
5. apply the transfromation from the file `certlcstats.transformation`
6. fetch the **immutableId** fomr the DCR (`dcr-<string>`)
7. fetch the name of the stream (`Custom-certlc_CL`) from the DCR. Note: it is case sensitive!
8. on the DCR, assign the role of `Monitoring Metrics Publisher` to the identity of the Automation Account
9. use stream name, immmutable id, ingestion url, keyvault name as parameters for the `certlcstats.ps1` runbook

