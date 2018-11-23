perl -pe 'chomp if eof' signed_info.xml | 
  xml c14n --without-comments - |
  openssl dgst -sha1 -sign privkey.pem |
  openssl base64