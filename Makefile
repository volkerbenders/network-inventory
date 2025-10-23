test:
	pytest
coverage_cache:
	pytest --cov-report term --cov-report xml:cache_coverage.xml --cov-report markdown:cache_coverage.md --cov=mac_vendor_cache
coverage_scanner:
	pytest --cov-report term --cov-report xml:scanner_coverage.xml --cov-report markdown:scanner_coverage.md --cov=network_scanner