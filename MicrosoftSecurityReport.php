<?php

set_time_limit( 0 );
//require "." . DIRECTORY_SEPARATOR . "CsvOut.php";

class WindowsUpdateIds {
	/** @var $date 日付 */
	public $date = array( );

	/** @var $kbNumber Microsoft技術文書に関する番号 */
	public $kbNumber = array( );
	public $kbNumberTwo = array( );

	/** @var $articleUrl 追加情報リンク **/
	public $articleUrl = array( );
	public $articleUrlTwo = array( );

	/** @var $deitail 詳細情報 */
	public $deitail  = array( );

	/** @var $articleUrl 詳細情報リンク */
	public $deitailUrl  = array( );

	/** @var $product 製品 */
	public $product  = array( );

	/** @var $severity 深刻度 */
	public $severity  = array( );

	/** @var $impact 影響度 */
	public $impact  = array( );

	/** @var $fullProductName 製品主キー */
	public $fullProductName  = array( );

}

if( !is_null( $_SERVER[ 'DOCUMENT_ROOT' ] ) ) print "<!DOCTYPE html><html><head><meta charset='UTF-8'></head>";

/**
 * 脆弱性情報データベース 非営利団体MITRE社 から追加情報を取得します。
 * $myWindowsUpdayeIds->deitail変数を'?name={この部分に当てはめて使用}'
 *
 * @link https://cve.mitre.org/index.html
 * @var $cveAdditionalInfoUrlBase CVE情報取得先URLを指定
 */
$cveAdditionalInfoUrlBase = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=";
$test = "http://cve.circl.lu/api/cve/";

$articleUrlBase = "https://support.microsoft.com/ja-jp/help/";

/**
 * RESTful API キーの取得には、Microsoft Account が必要になります。
 *
 * @link https://portal.msrc.microsoft.com/ja-JP/developer RESTful APIキー取得先
 * @var $api_key xxxに自分のAPIKeyを入力
 */
$api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

/** @var  $windowsReportDate Windows SecurityReport取得月を指定 */
$windowsReportDate = "2019-Dec"; /* YYYY-M 形式 例 : {取得年}-{各月の頭三文字} = 2019-Dec */

var_dump( $windowsReportDate );

$restUrl = "https://api.msrc.microsoft.com/cvrf/" . $windowsReportDate . "?api-version=2017";
/**
 * json 形式で取得します。
 *
 * @var $api_key RESTful API キーを指定
 */
$restfulCurlOptHeader = array( 'Accept: application/json', 'api-key: ' . $api_key );

$restfulCurlRet = Curl( $restfulCurlOptHeader, $restUrl, true );

$result = $restfulCurlRet[ 0 ]; // 生 json データを渡す
$data = $restfulCurlRet[ 1 ]; // 生 json データを連想配列化したものを渡す

if( file_exists( "." . DIRECTORY_SEPARATOR . "msrc.json" ) ) unlink( "." . DIRECTORY_SEPARATOR . "msrc.json" );
error_log( $result . PHP_EOL, 3, "." . DIRECTORY_SEPARATOR . "msrc.json" );
//var_dump( $data );

$productIds = array( );
$productIdsOs = array( );
$myWindowsUpdayeIds = new WindowsUpdateIds( );

for( $i = 0; $i < count( $data[ "ProductTree" ][ "FullProductName" ] ); $i++ ) {
	//print PHP_EOL . "<p>製品主キー ( FullProductName ) " . $i . " : " . $data[ "ProductTree" ][ "FullProductName" ][ $i ][ "Value" ];
	//print PHP_EOL . "<p>製品主キー ( FullProductName ) " . $i . " : " . $data[ "ProductTree" ][ "FullProductName" ][ $i ][ "ProductID" ];
	$productIds[ $i ] = $data[ "ProductTree" ][ "FullProductName" ][ $i ][ "ProductID" ];
	$productIdsOs[ $i ] = $data[ "ProductTree" ][ "FullProductName" ][ $i ][ "Value" ];

}

for( $i = 0; $i < count( $data[ "Vulnerability" ] ); $i++ ) {
	if( isset( $data[ "Vulnerability" ][ $i ][ "Remediations" ] ) ) {
		for( $y = 0; $y < count( $data[ "Vulnerability" ][ $i ][ "Remediations" ] ); $y++ ) {
			if( isset( $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ] ) ) {
				for( $z = 0; $z < count( $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ] ); $z++ ) {
					for( $x = 0; $x < count( $productIds ); $x++ ) {
						if( isset( $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ][ "ProductID" ][ $z ]  ) && isset( $productIds[ $x ] ) ) {
							if( $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ][ "ProductID" ][ $z ] == $productIds[ $x ] ) {
								print PHP_EOL . "<p>追加情報 ( KB 番号 ) : " . $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ][ "Description" ][ "Value" ];
								print PHP_EOL . "<p>追加情報 ( Article URL ) : " . $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ][ "URL" ];

								$myWindowsUpdayeIds->kbNumber[ $x ] = array( $productIds[ $x ], $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ][ "Description" ][ "Value" ] );
								$myWindowsUpdayeIds->articleUrl[ $x ] = array( $productIds[ $x ], $data[ "Vulnerability" ][ $i ][ "Remediations" ][ $y ][ "URL" ] );

							}

						}

					}

				}

			}

		}

	}

}

var_dump( $myWindowsUpdayeIds->kbNumber );
var_dump( $myWindowsUpdayeIds->articleUrl );
var_dump( $productIds );

$cntids = 0;
$idlists = array( -1 );

for( $i = 0; $i < count( $data[ "Vulnerability" ] ); $i++ ) {
	for( $y = 0; $y < count( $data[ "Vulnerability" ][ 0 ][ "ProductStatuses" ][ 0 ][ "ProductID" ] ); $y++ ) {
		if( isset( $data[ "Vulnerability" ][ $y ][ "ProductStatuses" ][ 0 ][ "ProductID" ] ) ) {
			for ( $x = 0; $x < count( $productIds ); $x++ ) {
				if( isset( $data[ "Vulnerability" ][ $i ][ "ProductStatuses" ][ 0 ][ "ProductID" ][ $y ] ) && isset( $productIds[ $x ] ) ) {
					if( $data[ "Vulnerability" ][ $i ][ "ProductStatuses" ][ 0 ][ "ProductID" ][ $y ] == $productIds[ $x ] ) {
						if( $productIdsOs[ $x ] != "None Available" ) {
							//print PHP_EOL . "<p>製品 ( Product ) : " . $data[ "Vulnerability" ][ $i ][ "Notes" ][ 1 ][ "Title" ];
							//if( !strpos( $productIdsOs[ $x ] ,"Server" ) === false ||
								//	!strpos( $productIdsOs[ $x ] ,"Internet Explorer" ) === false ) {
								print PHP_EOL . "<p>製品 ( Product ) : " . $productIdsOs[ $x ];
								preg_match( "/[0-9]{4}-[0-9]{2}-[0-9]{2}/", $data[ "Vulnerability" ][ $i ][ "RevisionHistory" ][ 0 ][ "Date" ], $tmpDate );
								print PHP_EOL . "<p>日付 ( Date ) : " . $tmpDate[ 0 ];
								print PHP_EOL . "<p>製品 ( Product ) : " . $data[ "Vulnerability" ][ $i ][ "Notes" ][ 1 ][ "Title" ];
								print PHP_EOL . "<p>詳細 ( Details ) : " . $data[ "Vulnerability" ][ $i ][ "CVE" ];
								print PHP_EOL . "<p>深刻度 ( Severity ) : " . $data[ "Vulnerability" ][ $i ][ "Threats" ][ 1 ][ "Description" ][ "Value" ];
								print PHP_EOL . "<p>影響度 ( Impact ) : " . $data[ "Vulnerability" ][ $i ][ "Threats" ][ 0 ][ "Description" ][ "Value" ];

								$cntids++;

								//$mytest = Curl( $restfulCurlOptHeader, $test . $data[ "Vulnerability" ][ $i ][ "CVE" ], true );
								//print PHP_EOL . "おいしいね : " . $mytest[ 1 ][ "references" ][ 0 ];
								//print PHP_EOL . "<p>詳細 ( Details URL ) : " . str_replace( "en-US", "ja-JP", $mytest[ 1 ][ "references" ][ 0 ] );

								for( $idlistsx = 0; $idlistsx < count( $idlists ); $idlistsx++ ) {
									if( strpos( $idlists[ $idlistsx ], $data[ "Vulnerability" ][ $i ][ "CVE" ] ) === false ) {
										preg_match_all( "(https?://[-_.!~*\'()a-zA-Z0-9;/?:@&=+$,%#]+)", Curl( array( null ), $cveAdditionalInfoUrlBase . $data[ "Vulnerability" ][ $i ][ "CVE" ], false ), $tmp[ $cntids ] );
										$idlists[ $idlistsx ] = $data[ "Vulnerability" ][ $i ][ "CVE" ];
										var_dump( $idlists );

									}

								}

								for( $arty = 0; $arty < count( $myWindowsUpdayeIds->articleUrl ); $arty++ ) {
									// product id ( 追加情報 ) と product id ( for roop 内 ) 比較
									if( $myWindowsUpdayeIds->articleUrl[ $arty ][ 0 ] == $productIds[ $x ] ) {
										$myWindowsUpdayeIds->kbNumberTwo[ $cntids ] = $myWindowsUpdayeIds->kbNumber[ $arty ][ 1 ];
										$myWindowsUpdayeIds->articleUrlTwo[ $cntids ] = $myWindowsUpdayeIds->articleUrl[ $arty ][ 1 ];
										break;

									}

								}

 								$myWindowsUpdayeIds->date[ $cntids ] = $tmpDate[ 0 ];
 								$myWindowsUpdayeIds->product[ $cntids ] = $productIdsOs[ $x ];
 								$myWindowsUpdayeIds->deitail[ $cntids ] = $data[ "Vulnerability" ][ $i ][ "CVE" ];
 								$myWindowsUpdayeIds->severity[ $cntids ] = $data[ "Vulnerability" ][ $i ][ "Threats" ][ 1 ][ "Description" ][ "Value" ];
 								$myWindowsUpdayeIds->impact[ $cntids ] = $data[ "Vulnerability" ][ $i ][ "Threats" ][ 0 ][ "Description" ][ "Value" ];

 								//for( $tmpx = 0; $tmpx < count( $tmp, COUNT_RECURSIVE ); $tmpx++ ) {
								//	print PHP_EOL . "<p>no isset tmpx : " . count( $tmp ) . "</p>";
									//if( isset( $tmp[ $tmpx ] ) ) {
 									if( isset( $tmp[ $cntids ] ) ) {
										for( $tmpy = 0; $tmpy < count( $tmp[ $cntids ] ); $tmpy++ ) {
											for( $tmpz = 0; $tmpz < count( $tmp[ $cntids ][ $tmpy ] ); $tmpz++ ) {
												if( !strpos( $tmp[ $cntids ][ $tmpy ][ $tmpz ], "security-guidance" ) === false ) {
													//if( !strpos( $tmp[ $cntids ][ $tmpy ][ $tmpz ], "CVE-2019-1476" ) === false ) {
														print PHP_EOL . "<p>詳細 ( Details URL ) : " . str_replace( "en-US", "ja-JP", $tmp[ $cntids ][ $tmpy ][ $tmpz ] );
														$myWindowsUpdayeIds->deitailUrl[ $cntids ] = str_replace( "en-US", "ja-JP", $tmp[ $cntids ][ $tmpy ][ $tmpz ] );
														break;

													//}

												}

											}

										}

 									} else {
 										if( !is_null( $myWindowsUpdayeIds->deitailUrl[ $cntids - 1 ] ) ) {
 											$myWindowsUpdayeIds->deitailUrl[ $cntids ] = $myWindowsUpdayeIds->deitailUrl[ $cntids - 1 ];
 											$myWindowsUpdayeIds->deitail[ $cntids ] = $myWindowsUpdayeIds->deitail[ $cntids - 1 ];

 										} else {
 											$myWindowsUpdayeIds->deitailUrl[ $cntids - 1 ] = "https://portal.msrc.microsoft.com/ja-JP/security-guidance/advisory/" . $data[ "Vulnerability" ][ $i ][ "CVE" ];
 											$myWindowsUpdayeIds->deitailUrl[ $cntids - 0 ] = "https://portal.msrc.microsoft.com/ja-JP/security-guidance/advisory/" . $data[ "Vulnerability" ][ $i ][ "CVE" ];

 											$myWindowsUpdayeIds->deitail[ $cntids - 1 ] = $data[ "Vulnerability" ][ $i ][ "CVE" ];
 											$myWindowsUpdayeIds->deitail[ $cntids - 0 ] = $data[ "Vulnerability" ][ $i ][ "CVE" ];

 										}

 										break;

 									}

								//}
								print PHP_EOL . "<hr>";
								//$myWindowsUpdayeIds->articleUrl[ $cntids ] = "test.code.com";

							//}

							//print "<p>test : " . $myWindowsUpdayeIds->articleUrl[ 0 ] . "</p>";
							//var_dump( $myWindowsUpdayeIds->articleUrl );

							//$list = array (
							//	array( "日付", "追加情報" ),
							//	array( $myWindowsUpdayeIds->date[ 0 ], '=HYPERLINK("' . $myWindowsUpdayeIds->articleUrl[ 0 ] . '","' . $myWindowsUpdayeIds->deitail[ 0 ] . '")' )
							//);

							//}
							//}

							//var_dump( $list );
							//print "<p>" . $list[ 1 ][ 1 ] . "</p>";

							//$fp = fopen( "." . DIRECTORY_SEPARATOR . 'file.csv', 'a');

							//foreach( $list as $fields ) {
							//	fputcsv( $fp, $fields );

							//}

							//fclose($fp);

						}

					}

				}

			}

		}

	}

}

//$myCsvOut = new CsvOut( );
//$myCsvOut->setFormat(
//	array(
//		array( "日付", "追加情報", "製品", "詳細", "深刻度", "OS絞込み" ),
//		array( $myWindowsUpdayeIds->date, '=HYPERLINK(\"\"' . $myWindowsUpdayeIds->articleUrl . '\"\";\"\"' . $myWindowsUpdayeIds->deitail . '\"\")", "O" )',
//		array( "ジョン", "23", "A" ),
//		array( "ニキータ", "32", "AB" ),
//		array( "次郎", "22", "B" )

//	)

//);

//var_dump( $myWindowsUpdayeIds );
print "<p>myWindowsUpdayeIds->product<br><pre>" . print_r( $myWindowsUpdayeIds->product ) . "</pre></p>";
//var_dump( $myWindowsUpdayeIds->articleUrlTwo );
//var_dump( $myWindowsUpdayeIds->kbNumberTwo );

/*array( "日付", "追加情報" ),*/

// カウント値を待避しておく
$cntTaihi = count( $myWindowsUpdayeIds->date );

$list = array( );

print "<p>count list before : " . count( $list ) . "</p>";

for( $listx = 0; $listx < count( $myWindowsUpdayeIds->date ); $listx++ ) {

	//if( !Search( "Server Core installation", $myWindowsUpdayeIds->product[ $listx ] ) ) {

		if( Search( "Windows Server 2008 R2 for x64-based Systems Service Pack 1", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Windows Server 2008 for 32-bit Systems Service Pack 2", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Windows Server 2008 for x64-based Systems Service Pack 2", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Windows Server 2012", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Windows Server 2016", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Windows Server 2019", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "SQL	Windows Server 2012 R2	Windows Server 2012 R2", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "SQL Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Internet Explorer 6 on Windows Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Internet Explorer 7 on Windows Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Internet Explorer 8 on Windows Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Internet Explorer 9 on Windows Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Internet Explorer 10 on Windows Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "Internet Explorer 11 on Windows Server", $myWindowsUpdayeIds->product[ $listx ] ) ||
			Search( "IIS", $myWindowsUpdayeIds->product[ $listx ] ) ) {

			if( isset( $myWindowsUpdayeIds->date[ $listx ] ) ) {

				$list[ $listx ] = array (
				    $myWindowsUpdayeIds->date[ $listx ],
					'=HYPERLINK("' . $myWindowsUpdayeIds->articleUrlTwo[ $listx ] . '","' . $myWindowsUpdayeIds->kbNumberTwo[ $listx ] . '")',
					$myWindowsUpdayeIds->product[ $listx ],
					'=HYPERLINK("' . $myWindowsUpdayeIds->deitailUrl[ $listx ] . '","' . $myWindowsUpdayeIds->deitail[ $listx ] . '")',
					$myWindowsUpdayeIds->severity[ $listx ],
					$myWindowsUpdayeIds->impact[ $listx ]

				);

			}

		}

	//}

}

print "<p>count list after : " . count( $list ) . "</p>";
print "<p>count cntTaihi : " . count( $cntTaihi ) . "</p>";

// var_dump( $idlists );
// var_dump( $tmp );

print PHP_EOL . "<p>no isset tmpx : " . count( $tmp, COUNT_RECURSIVE ) . "</p>";

if( file_exists( "." . DIRECTORY_SEPARATOR . "file.csv" ) ) unlink( "." . DIRECTORY_SEPARATOR . "file.csv" );

$fp = fopen( "." . DIRECTORY_SEPARATOR . 'file.csv', 'a');
stream_filter_prepend( $fp, 'convert.iconv.utf-8/cp932' );

fputcsv( $fp, array( "日付", "追加情報", "製品", "詳細", "深刻度", "影響度" ) );

for( $csvz = 0; $csvz < $cntTaihi; $csvz++ ) {
	//for( $csvy = 0; $csvy < count( $list[ $csvz ] ); $csvy++ ) {
		//print PHP_EOL . "<p>list debug : " . $list[ $csvz ][ $csvy ] . "</p>";
		//print PHP_EOL . "<p>list count debug : " . $list[ $csvz ][ $csvy ][ 0 ] . "</p>";
		if( isset( $list[ $csvz ] ) ) fputcsv( $fp, $list[ $csvz ] );

		//for( $csvx = 0; $csvx < count( $list[ $csvz ][ $csvy ] ); $csvx++ ) {
		//	if( isset( $list[ $csvz ][ $csvy ][ $csvx ] ) ) {
		//		print PHP_EOL . "<p>list debug info : " . $list[ $csvz ][ $csvy ][ $csvx ] . "</p>";
		//		fputcsv( $fp, $list[ $csvz ][ $csvy ][ $csvx ] );

		//	}

		//}

	//}

}

fclose( $fp );




/**
 * インターネットから URL を指定して情報を取得する関数
 *
 * @param array $arr Header オプションを指定する場合は配列で指定
 * @param string $url 情報取得先 URL を指定
 * @param bool $isHeader Header オプションを使うか否かを指定 default : false : 使用しない, ture : 使用する
 *
 * @return array curl 結果を返す, 生 json data を連想配列にした変数 を返す, 処理に失敗した場合 false を返す
 * @throws Exception Curl 実行中にエラーが起きた際にエラー情報が投げられる
 */
function Curl( array $arr, $url, $isHeader = false ) {

	$ch = curl_init( );
	if( $isHeader ) curl_setopt( $ch, CURLOPT_HTTPHEADER, $arr ); // Set The Response Format to Json
	curl_setopt( $ch, CURLOPT_CUSTOMREQUEST, "GET" ); // using cURL for a GET request
	curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false ); // SSL 検証無効化
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true ); //文字列で結果を返させる
	curl_setopt( $ch, CURLOPT_URL, $url );
	$result = curl_exec( $ch );
	$curlError = array( curl_error( $ch ), curl_errno( $ch ) );
	curl_close( $ch );

	var_dump( mb_detect_encoding( $result ) );

	try {
		if( $curlError[ 0 ] != null && $curlError[ 1 ] != 0 ) throw new \Exception( "curl faild" );

		if( $isHeader ) {

			$data = json_decode( $result, true );
			switch ( json_last_error() ) {
				case JSON_ERROR_NONE:
					echo ' - No errors';
					break;
				case JSON_ERROR_DEPTH:
					echo ' - Maximum stack depth exceeded';
					break;
				case JSON_ERROR_STATE_MISMATCH:
					echo ' - Underflow or the modes mismatch';
					break;
				case JSON_ERROR_CTRL_CHAR:
					echo ' - Unexpected control character found';
					break;
				case JSON_ERROR_SYNTAX:
					echo ' - Syntax error, malformed JSON';
					break;
				case JSON_ERROR_UTF8:
					echo ' - Malformed UTF-8 characters, possibly incorrectly encoded';
					break;
				default:
					echo ' - Unknown error';
					break;

			}

			return array( $result, $data ); // 生 json data, 生 json data を連想配列にした変数 を返す

		}

		if( !$isHeader ) return $result; // curl 結果を返す

	} catch ( \Exception $e ) {
		var_dump( $e->getMessage( ) );

		$result = false;

	}

}

/**
 * 文字データからマッチしたか否かを判定します
 *
 * @param string $w 検索したい文字列を指定します
 * @param string $logData 文字データを指定します
 * @return boolean $isMatch 対象ログから指定した文字列がマッチした場合, true, しなかった場合, false を返します
 */
function Search( $w = null, $logData = null, $debug = 0 ) {
	$isMatch = 0; // マッチしたか格納する変数

	if( is_null( $w ) || is_null( $logData ) ) print "<p>引数エラー 引数が足りないもしくは値が空です。</p>";
	if( strpos( $logData, $w ) !== false ) {
		$isMatch = 1;
		if( $debug ) print PHP_EOL . "<p>" . $w . " は引数 logData に含まれていました。" . "</p>" . PHP_EOL;

	} else if( $debug ) print PHP_EOL . "<p>" . $w . " は引数 logData に含まれていませんでした。" . "</p>" . PHP_EOL;

	return $isMatch;

}
