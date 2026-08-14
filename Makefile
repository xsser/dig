.PHONY: test verify

test:
	./tests/test_wrapper.sh
	/usr/bin/python3 tests/test_install_restore.py

verify:
	/usr/bin/python3 -m py_compile src/dig_wrapper.py
	/usr/bin/python3 -m py_compile scripts/validate_archive.py
	/bin/sh -n scripts/install.sh
	/bin/sh -n scripts/restore.sh
	/bin/sh -n tests/test_wrapper.sh
	/usr/bin/python3 -m py_compile tests/test_install_restore.py
	./tests/test_wrapper.sh
	/usr/bin/python3 tests/test_install_restore.py
