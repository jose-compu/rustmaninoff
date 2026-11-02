# Checkov coverage inventory (rustmaninoff)

Generated from `crates/cli/policies`.
**Built-in checks:** 185

## By framework directory

| Framework | Count |
| --- | ---: |
| cloudformation | 51 |
| docker | 4 |
| kubernetes | 32 |
| terraform | 98 |

## By CKV family

| Family | Count |
| --- | ---: |
| CKV2 | 4 |
| CKV_AWS | 145 |
| CKV_DOCKER | 4 |
| CKV_K8S | 32 |

## Notes

- Checkov denominator and gap columns are filled when `tools/checkov-ids/` is added (#42).
- Graph checks (`CKV2_*`) are a first-wave AWS subset, not full Checkov graph parity.
- Intentional gaps (Helm, plan JSON, secrets, CVE) stay out of this inventory.

