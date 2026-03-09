# Contributing to PublicEye

## Adding Modules

1. Create a new class in `publiceye.py` following the existing pattern.
2. Implement a static `run(target)` method returning a results dict.
3. Add the module to `MODULE_MAP` in the `main()` function.
4. Use `log()`, `safe_request()`, and `concurrent.futures` for consistency.
5. Document the module in README.md.

## Code Standards

- Python 3.8+ compatible
- Type hints encouraged
- Use `safe_request()` for all HTTP calls
- Graceful degradation when optional libraries missing
- No exploitation or destructive capabilities

## Commit Messages

Use: `add:`, `fix:`, `docs:`, `refactor:`, `test:`
