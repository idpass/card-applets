
# Common implied folder locations for this build
outdir=${t}/build
gp211=libs-sdks/jc304_kit/lib/api_classic.jar:libs/globalplatform-2_1_1/gp211.jar
jars=libs-sdks/jc304_kit/lib/api_classic.jar:$(outdir)/org.idpass.tools.jar 

PKGIDTOOLS=0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x00
PKGIDAUTH=0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x01
PKGIDSAM=0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x02
APPLETIDAUTH=0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x01:0x01:0x00:0x01
APPLETIDSAM=0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x02:0x01:0x00:0x01

javasource=1.6
javatarget=1.6

all: outdir $(outdir)/org/idpass/tools/javacard/tools.cap $(outdir)/org/idpass/auth/javacard/auth.cap $(outdir)/org/idpass/sam/javacard/sam.cap
	@echo
	@echo "************************************"
	@echo "*** LISTING GENERATED CAP FILES ***"
	@find ${t}/build/ -type f -name '*.cap' 
	@echo

outdir:
	@mkdir -p $(outdir)

circleci_env_check:
	@echo "*** CIRCLECI ENVIRONMENT ***"
	pwd
	git remote -v
	cat .gitmodules
	ls
	find . -type f -name '*.java'

$(outdir)/org.idpass.tools.jar: $(outdir)/org/idpass/tools/*.class
	jar cvf $(outdir)/org.idpass.tools.jar -C $(outdir)/ .

$(outdir)/org/idpass/tools/*.class: ${t}/src/main/java/org/idpass/tools/*.java
	javac -source $(javasource) -target $(javatarget) -d $(outdir) -cp $(gp211) ${t}/src/main/java/org/idpass/tools/*.java

$(outdir)/org/idpass/auth/*.class: ${t}/src/main/java/org/idpass/auth/*.java
	javac -source $(javasource) -target $(javatarget) -cp $(jars) -d $(outdir) ${t}/src/main/java/org/idpass/auth/*.java

$(outdir)/org/idpass/sam/*.class: ${t}/src/main/java/org/idpass/sam/*.java
	javac -source $(javasource) -target $(javatarget) -cp $(jars) -d $(outdir) ${t}/src/main/java/org/idpass/sam/*.java

$(outdir)/org/idpass/tools/javacard/tools.cap: $(outdir)/org.idpass.tools.jar
	./convert.sh \
		org.idpass.tools \
		$(PKGIDTOOLS)

$(outdir)/org/idpass/auth/javacard/auth.cap: $(outdir)/org/idpass/auth/*.class $(outdir)/org/idpass/tools/javacard/tools.cap
	./convert.sh \
		org.idpass.auth \
		$(PKGIDAUTH) \
		$(APPLETIDAUTH) \
		org.idpass.auth.AuthApplet 

$(outdir)/org/idpass/sam/javacard/sam.cap: $(outdir)/org/idpass/sam/*.class $(outdir)/org/idpass/tools/javacard/tools.cap
	./convert.sh \
		org.idpass.sam \
		$(PKGIDSAM) \
		$(APPLETIDSAM) \
		org.idpass.sam.SamApplet

clean:
	@rm -rf $(outdir)/*
.PHONE: clean
