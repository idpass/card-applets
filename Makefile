
# Common implied folder locations for this build
outdir=build
gp211=libs-sdks/jc304_kit/lib/api_classic.jar:libs/globalplatform-2_1_1/gp211.jar
jars=libs-sdks/jc304_kit/lib/api_classic.jar:$(outdir)/org.idpass.tools.jar 

all: outdir $(outdir)/org/idpass/tools/javacard/tools.cap $(outdir)/org/idpass/auth/javacard/auth.cap $(outdir)/org/idpass/sam/javacard/sam.cap
	@echo
	@echo "************************************"
	@echo "*** LISTING GENERATED CAP FILES ***"
	@find build/ -type f -name '*.cap' 
	@echo

outdir:
	@mkdir -p build/

circleci_env_check:
	@echo "*** CIRCLECI ENVIRONMENT ***"
	pwd
	git remote -v
	cat .gitmodules
	ls
	find . -type f -name '*.java'

$(outdir)/org.idpass.tools.jar: $(outdir)/org/idpass/tools/*.class
	jar cvf $(outdir)/org.idpass.tools.jar -C $(outdir)/ .

$(outdir)/org/idpass/tools/*.class: src/main/java/org/idpass/tools/*.java
	javac -source 1.2 -target 1.2 -d $(outdir) -cp $(gp211) src/main/java/org/idpass/tools/*.java

$(outdir)/org/idpass/auth/*.class: src/main/java/org/idpass/auth/*.java
	javac -source 1.2 -target 1.2 -cp $(jars) -d $(outdir) src/main/java/org/idpass/auth/*.java

$(outdir)/org/idpass/sam/*.class: src/main/java/org/idpass/sam/*.java
	javac -source 1.2 -target 1.2 -cp $(jars) -d $(outdir) src/main/java/org/idpass/sam/*.java

$(outdir)/org/idpass/tools/javacard/tools.cap: $(outdir)/org.idpass.tools.jar
	./convert.sh org.idpass.tools 0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x0 

$(outdir)/org/idpass/auth/javacard/auth.cap: $(outdir)/org/idpass/auth/*.class $(outdir)/org/idpass/tools/javacard/tools.cap
	./convert.sh org.idpass.auth  0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x1 

$(outdir)/org/idpass/sam/javacard/sam.cap: $(outdir)/org/idpass/sam/*.class $(outdir)/org/idpass/tools/javacard/tools.cap
	./convert.sh org.idpass.sam   0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x2

clean:
	@rm -rf $(outdir)/*
.PHONE: clean
