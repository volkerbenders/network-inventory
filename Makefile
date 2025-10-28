network=192.168.178.0/24
requirements:
	pip install -r requirements.txt
	sudo pip install -r requirements.txt
scan:
	sudo python network_scanner.py -n $(network)
test:
	pytest
coverage_cache:
	pytest --cov-report term --cov-report xml:cache_coverage.xml --cov-report html:cache_coverage.html --cov-report markdown:cache_coverage.md --cov=mac_vendor_cache
coverage_scanner:
	pytest --cov-report term --cov-report xml:scanner_coverage.xml --cov-report markdown:scanner_coverage.md --cov=network_scanner
