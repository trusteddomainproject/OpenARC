# Copyright (c) 2010-2014, 2016, 2017, The Trusted Domain Project.
# All rights reserved.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = libopenarc contrib docs openarc
dist_doc_DATA = LICENSE LICENSE.Sendmail RELEASE_NOTES
dist_noinst_SCRIPTS = libtool

DISTCLEANFILES = openarc-@VERSION@.tar.gz

# TODO: get configure.ac to generate --enable-{feature} for all
# non-experimental features and substitute it here e.g  @SUPPORTED_FEATURES@.
# Perhaps all features would enable a more comprehensive test coverage map
# though.
DISTCHECK_CONFIGURE_FLAGS=--with-openssl=/usr/local

$(DIST_ARCHIVES): distcheck

$(DIST_ARCHIVES).md5: $(DIST_ARCHIVES)
	md5 $? > $@ || md5sum $? > $@

$(DIST_ARCHIVES).sha1: $(DIST_ARCHIVES)
	sha1 $? > $@ || sha1sum $? > $@

$(DIST_ARCHIVES).asc: $(DIST_ARCHIVES)
	gpg -a -u security@trusteddomain.org --detach-sign $?

push: $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).md5 $(DIST_ARCHIVES).asc
	@echo "Are you sure you want to tag and release $(DIST_ARCHIVES)? (y/n)"
	@read confirm && [ $$confirm = 'y' ]
	git tag rel-openarc-`echo $(VERSION) | sed 's/\./-/g'`
	git push --tags

dist-hook:
	[ -f $(distdir)/libopenarc/arc.h ] && rm -f $(distdir)/libopenarc/arc.h
	sed -e '/OPENARC_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopenarc/arc.h > $(distdir)/libopenarc/arc.h
	echo "looking to see if @VERSION@ is in the RELEASE_NOTES"
	fgrep @VERSION@ $(srcdir)/RELEASE_NOTES
	sed -e 's|\(@VERSION@[ \t]*\)[0-9?]\{4\}\(/[0-9?]\{2\}\)\{2\}|\1'`date +%Y/%m/%d`'|' < $(srcdir)/RELEASE_NOTES > $(distdir)/RELEASE_NOTES

rpm: dist-gzip
	rpmbuild -ta $(distdir).tar.gz

docker:
	@if [[ ! -f /var/run/docker.pid ]]; then echo "Error: Docker is not installed or not running!" ; exit 1 ; fi
	@if [[ ! -f $(keyfile) ]]; then echo "Error: $(keyfile) does not exist!" ; exit 1 ; fi
	docker -v \
	&& docker rm -f openarc \
	; docker build . -t openarc --build-arg KEYFILE=$(keyfile) --build-arg SELECTOR=$(selector) --build-arg DOMAIN=$(domain) \
	&& docker run --name openarc -p 22:22 -p 8894:8894 -dit openarc

.PHONY: push
