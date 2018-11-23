perl -pe 'chomp if eof' envelope.xml |
  xml edit -P -N x="http://www.w3.org/2000/09/xmldsig#" --delete "//x:Signature" |
  xml c14n --exc-without-comments - |
  openssl sha256 -binary |
  openssl base64 -A