# AI Exposure Analyzer — integrated into PoV Manager

The **scanner engine** and **`config/patterns.yaml`** were moved to the importable Python package:

- `pov_manager/ai_exposure/scanner/`
- `pov_manager/ai_exposure/config/`

Use the analyzer from Django via:

- **UI:** Threat Profile row → **AI exposure scan** (requires `organization_domain`)
- **CLI:** `python manage.py run_ai_exposure_scan --profile-uuid <UUID>`
- **Code:** `from ai_exposure.engine import run_ai_exposure_scan`

The former **FastAPI** app (`webapi/`), **React UI** (`ui/`), and **demo** scripts remain here for reference only; they are not required for PoV Manager operation.
