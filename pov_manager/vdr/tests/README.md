# VDR App Unit Tests

Comprehensive unit test suite for the VDR (Vulnerability Detection and Reporting) application.

## Test Coverage

This test suite provides comprehensive coverage of the VDR app components:

### 1. **test_utils.py** - Utility Functions (HIGH PRIORITY)
- IP address conversion and validation
- IP range validation (public/private detection)
- Vulnerability processing and Excel generation
- **~180 assertions across 30+ test cases**

### 2. **test_models.py** - Django Models
- ThreatProfile model CRUD operations
- Vulnerabilities model operations
- Field validation and constraints
- Foreign key relationships and cascade deletion
- **~90 assertions across 20+ test cases**

### 3. **test_vdrapi.py** - VDR API Client (HIGH PRIORITY)
- All 23 API interaction functions
- HTTP request/response handling
- Error handling and custom exceptions
- Tag, range, server, and website operations
- Schedule management and cleanup operations
- **~130 assertions across 50+ test cases**

### 4. **test_ctuapi.py** - CTU API Client
- Report submission and status checking
- File download operations
- Error handling for network issues
- **~45 assertions across 15+ test cases**

### 5. **test_commands.py** - Management Commands (HIGH PRIORITY)
- Report fetching with retry logic
- CSV parsing and data processing
- Vulnerability aggregation and statistics
- VDR data building for CTU reports
- Complete workflow orchestration
- **~120 assertions across 40+ test cases**

### 6. **test_forms.py** - Django Forms
- Form validation
- Field requirements and constraints
- Model binding
- **~25 assertions across 8+ test cases**

### 7. **factories.py** - Test Data Factories
- Model factories for clean test data generation
- Multiple factory variants for different scenarios

### 8. **conftest.py** - Pytest Configuration
- Shared fixtures across all tests
- Test settings configuration
- Mock API response templates

## Total Test Statistics

- **~600 assertions**
- **200+ test cases**
- **All major code paths covered**
- **High-priority components fully tested**

## Running Tests

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run All Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=pov_manager/vdr --cov-report=html --cov-report=term

# Run with verbose output
pytest -v

# Run specific test file
pytest pov_manager/vdr/tests/test_utils.py

# Run specific test class
pytest pov_manager/vdr/tests/test_utils.py::TestIPRangeValidation

# Run specific test
pytest pov_manager/vdr/tests/test_utils.py::TestIPRangeValidation::test_valid_public_ip_ranges
```

### Run Tests by Marker

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run slow tests
pytest -m slow
```

### Generate Coverage Report

```bash
# Generate HTML coverage report
pytest --cov=pov_manager/vdr --cov-report=html

# Open in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

## Test Organization

```
pov_manager/vdr/tests/
├── __init__.py
├── README.md              # This file
├── conftest.py           # Pytest configuration and fixtures
├── factories.py          # Model factories for test data
├── test_utils.py         # Utility function tests
├── test_models.py        # Model tests
├── test_vdrapi.py        # VDR API client tests
├── test_ctuapi.py        # CTU API client tests
├── test_commands.py      # Management command tests
└── test_forms.py         # Form validation tests
```

## Key Testing Patterns

### 1. Mocking External APIs

```python
@mock.patch('vdr.vdrapi.requests.post')
def test_create_tag_success(mock_post):
    mock_post.return_value.json.return_value = {'id': 12345}
    tag_id = create_tag('test_tag')
    assert tag_id == 12345
```

### 2. Using Model Factories

```python
def test_with_factory(db):
    profile = ThreatProfileFactory()
    vuln = VulnerabilitiesFactory(threat_profile=profile)
    assert vuln.threat_profile == profile
```

### 3. Parametrized Tests

```python
@pytest.mark.parametrize('ip_range,expected', [
    ('89.34.76.0/24', {'valid': True}),
    ('10.0.0.0/8', {'valid': False, 'error': 'private'}),
])
def test_validate_ip_range(ip_range, expected):
    result = validate_ip_range(ip_range)
    assert result == expected
```

### 4. Django Database Tests

```python
@pytest.mark.django_db
def test_model_creation(db):
    profile = ThreatProfile.objects.create(
        organization_name='Test',
        vivun_activity='123456'
    )
    assert profile.status == ThreatProfile.STATUS_CREATED
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run tests
        run: |
          pytest --cov=pov_manager/vdr --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## Test Maintenance

### Adding New Tests

1. Create test file following naming convention: `test_*.py`
2. Use appropriate markers: `@pytest.mark.unit`, `@pytest.mark.integration`
3. Mock external dependencies (APIs, file I/O, network)
4. Use factories for model creation
5. Follow existing patterns for consistency

### Best Practices

- **Keep tests independent**: Each test should be able to run in isolation
- **Use descriptive names**: Test names should clearly indicate what is being tested
- **Mock external services**: Never make real API calls in tests
- **Use factories**: Generate test data with factories, not manual creation
- **Test edge cases**: Include boundary conditions and error scenarios
- **Keep tests fast**: Unit tests should run in milliseconds
- **Maintain high coverage**: Aim for 80%+ code coverage

## Troubleshooting

### Common Issues

1. **Database errors**: Make sure to use `@pytest.mark.django_db` decorator
2. **Import errors**: Check that PYTHONPATH includes project root
3. **Settings errors**: Ensure Django settings are properly configured
4. **Mock issues**: Verify mock patch paths match actual import paths

### Debug Mode

```bash
# Run tests with Python debugger
pytest --pdb

# Show print statements
pytest -s

# Run last failed tests
pytest --lf

# Run tests matching a pattern
pytest -k "test_ip"
```

## Coverage Goals

- **Overall**: 80%+ coverage
- **High Priority Modules**:
  - `utils.py`: 90%+ (pure functions)
  - `vdrapi.py`: 85%+ (API client)
  - `ctuapi.py`: 85%+ (API client)
  - `models.py`: 80%+ (data layer)
  - `commands/`: 80%+ (business logic)

## Contributing

When adding new functionality to the VDR app:

1. Write tests first (TDD approach recommended)
2. Ensure all tests pass before committing
3. Add new fixtures to `conftest.py` if needed
4. Update factories for new models
5. Maintain test documentation

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-django documentation](https://pytest-django.readthedocs.io/)
- [factory_boy documentation](https://factoryboy.readthedocs.io/)
- [Django testing documentation](https://docs.djangoproject.com/en/stable/topics/testing/)


