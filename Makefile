.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./sprayer.egg-info/

docs:
	@python3 -m pip install pdoc
	@echo "[$(shell date)] Generating docs ..."
	@python3 -m pdoc -d markdown -o ./documentation/ ./sprayer/
	@echo "[$(shell date)] Done!"

install: build
	python3 -m pip uninstall sprayer
	python3 setup.py install

build:
	python3 setup.py sdist bdist_wheel

upload: build
	twine upload dist/*
