# https://github.com/cabo/kramdown-rfc/tree/master/examples

DRAFT = draft-justo-goe2ee-latest

default: all

all: install compile

install:
	gem install kramdown-rfc
	pip3 install xml2rfc

compile:
	kramdown-rfc $(DRAFT).md > $(DRAFT).xml
	xml2rfc $(DRAFT).xml --text --html

clean:
	rm -f $(DRAFT).xml $(DRAFT).txt $(DRAFT).html
	rm -rf .refcache
