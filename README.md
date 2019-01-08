# xmldsig-tests

Standards: https://www.w3.org/standards/techs/xmlsig

Quickstart:

```
git clone https://github.com/markusschuh/xmldsig-tests.git
```

```
cd xmldsig-tests
```

```
mvn compile
```

```
mvn exec:java -Dexec.mainClass="com.capgemini.de.xmldsigtests.CreateSignatureJSR105" -Dexec.args="src\test\resources\envelope.xml"
```

```
mvn exec:java -Dexec.mainClass="com.capgemini.de.xmldsigtests.CreateSignatureSanctuario" -Dexec.args="src\test\resources\envelope.xml"
```

```
mvn exec:java -Dorg.apache.xml.security.ignoreLineBreaks=true -Dexec.mainClass="com.capgemini.de.xmldsigtests.CreateSignatureSantuario" -Dexec.args="src\test\resources\envelope.xml"
```
