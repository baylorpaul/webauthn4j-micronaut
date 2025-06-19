# Publishing the library

As of February 1, 2024, Sonatype requires new accounts be created in [Maven Central](https://central.sonatype.com).
This means artifacts for new accounts must be published via the Central Portal, and they cannot be published via OSSRH.
Furthermore, ["there is no official Gradle plugin for publishing to Maven Central via the Central Publishing Portal"](https://central.sonatype.org/publish/publish-portal-gradle/)
yet. You may publish with a Maven plugin, the Publisher API, manually, or via third party Gradle plugins.

## Install GPG

Create public and private keys for signing.

	brew install gnupg
	gpg --full-gen-key
	gpg --keyserver keyserver.ubuntu.com --send-keys MY_PUBLIC_KEY_ID

## Increment the version

Update the `version` in `library/build.gradle`.

## Manual Upload

### Generate the artifacts

We could make a separate publication, but we're reusing the pom artifact that we're generating for GPR (GitHub Packages Repository).
Then copy the artifacts to a separate directory.
Finally, sign the artifacts with ASCII signature files (.asc) and generate checksums (.sha1 and .md5):

	./gradlew :library:clean :library:build :library:generatePomFileForGprPublication
	GROUPDIR=io/github/baylorpaul
	LIBNAME=webauthn4j-micronaut
	VERSION=$(ls library/build/libs/*-sources.jar | xargs -n 1 basename | sed 's/.*-\([\.0-9A-Za-z]*\)-sources.*/\1/')
	mkdir -p library/build/publications/maven-central/artifacts
	find library/build/libs -type f -name "library-$VERSION.jar" -or -name "library-$VERSION-javadoc.jar" -or -name "library-$VERSION-sources.jar" -or -name "library-$VERSION-tests.jar" | xargs -I {} cp {} library/build/publications/maven-central/artifacts/
	cp library/build/publications/gpr/pom-default.xml library/build/publications/maven-central/artifacts/$LIBNAME-$VERSION.pom
	pushd library/build/publications/maven-central/artifacts
	mv "library-$VERSION.jar" "$LIBNAME-$VERSION.jar"
	mv "library-$VERSION-javadoc.jar" "$LIBNAME-$VERSION-javadoc.jar"
	mv "library-$VERSION-sources.jar" "$LIBNAME-$VERSION-sources.jar"
	mv "library-$VERSION-tests.jar" "$LIBNAME-$VERSION-tests.jar"
	for FILE in *; do
		gpg --armor --detach-sign $FILE
		sha1sum $FILE | cut -d ' ' -f 1 > $FILE.sha1
		md5sum $FILE | cut -d ' ' -f 1 > $FILE.md5
	; done
	cd ..
	mkdir -p $GROUPDIR/$LIBNAME/$VERSION
	mv artifacts/* $GROUPDIR/$LIBNAME/$VERSION/
	rm -rf artifacts
	zip $LIBNAME-$VERSION.zip * $GROUPDIR/$LIBNAME/$VERSION/*
	rm -rf io
	popd

### Upload to Maven Central

Login to https://central.sonatype.com/

If you haven't already, "[Register/Add a Namespace](https://blog.samzhu.dev/2024/04/20/Publishing-Your-Package-to-Maven-Central-in-2024/#Register-a-Namespace)".

Now, "Publish Component". For the "Deployment Name", use e.g. `io.github.baylorpaul:webauthn4j-micronaut:1.1.3`
Upload the zip file in `library/build/publications/maven-central`
