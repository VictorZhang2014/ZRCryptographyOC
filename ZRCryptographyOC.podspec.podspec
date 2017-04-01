Pod::Spec.new do |spec|
    spec.name         = 'ZRCryptographyOC'
    spec.version      = '1.0'
    spec.license      = "MIT"
    spec.homepage     = 'https://github.com/VictorZhang2014/ZRCryptographyOC'
    spec.author       = { "Victor Zhang" => "victorzhangq@gmail.com" }
    spec.summary      = 'ZRCryptographyOC, a set of cryptographic methods which provides an easily way to call. It includes RSA,AES,DES,MD5,SHA1,SHA224,SHA384,SHA512 algorithms.'
    spec.source       = { :git => 'https://github.com/VictorZhang2014/ZRCryptographyOC.git', :tag => spec.version.to_s }
    spec.platform     = :ios
    spec.source_files = 'Classes/ZRCryptographyOC.{h,m}'
    spec.framework    = {'Foundation','Security'}
    spec.requires_arc = true
end
