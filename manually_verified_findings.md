# Manually Verified Vulnerable Extensions

These extensions were **manually verified as true positives** — each vulnerability was reproduced
by hand in a real browser (page-controlled payload → observed exploit: extension-initiated request,
data returned to an unauthorized page, or attacker-controlled data written to extension storage).
Every listed extension is a confirmed, exploitable vulnerability with no sender/origin check on the
message handler.

**Total: 30 extensions.**

## 1way_request (6)
Any web page can make the extension issue an attacker-controlled outbound request.

- feplmbiadapffhmchkpplffbahhpaiah
- hkfgkcjmohhngcmkcdohhapbnkfigedm
- joodfhmldgfiljoipdigbelmoncemfom
- ebeiohfighdabjhkklnghfofnnfglmad
- cflakfhockilljdbofnanaijpmpmfcol
- olngjdhppjohaikmfaebpdelhknnidae

## 2way_request (1)
Any web page can make the extension fetch a URL and receive the response body back (CORS bypass).

- domnlbhlhajgcadjicnpgofjfamplafh

## data_exfiltration (12)
Any web page can retrieve data the extension holds (storage, cookies, tokens, or backend responses).

- jhidcpailhmpjpbdbhceiaeeggkalgmd
- ghdgpmmhlakdfijglonimadabgalmode
- afmemjjekcdkgpnladhmgglocgfkaali
- hmhnpeiicgickafpejkeehjdknadjjlh
- ddojnmkongaimkdddgmcccldlfhokcfb
- pedmlpceiodameienmmkpkkpilgklmfh
- lhbkaepmdbbokbhfopdmjmnjmbnhhohn
- gdflafpepcpbfijbpgkmncfjbkbleeel
- ahmjnhhjmlbndpklcekkbkkdoehlledk
- niddencppjibifjjgaippjnoodlhcpjl
- bhaebpnlhphfjffkchdccafakpeimnpd
- mhepfpndlnjomjghloembdehlgfnicil

## storage (10)
Any web page can write attacker-controlled data into the extension's storage.

- nfneegfikdhioakbngdimhhcnaaaalne
- odlpbemmhhohkhalkeephidfkppinpla
- egehfamfcmkanpgeponfgielpepeochd
- opdgkfbbbfoaocohabnjffdflgddolhg
- boocpojecnmkjnapcfgfgejdglpamool
- egidcfnmmpdbnppnknhgogimbjpakflc
- mhfjjooonjbpiphgmddfmnhaflnfbong
- mkopigaglldpfgpjiommdoodnabdndhd
- dfahgnafbddihjlebeimhkhldlbceggh
- pjcikabglafjpmbgjklenakfegeaafdh

## Note
- `fooafgfobgknpeigkmebndddlepfldjm` (data_exfiltration) is Manifest V2; the vulnerable
  `onMessageExternal` handler was confirmed by source review (returns extension data to any page,
  no origin check).
