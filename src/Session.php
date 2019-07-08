<?php
namespace TymFrontiers;
class Session{
  private $_logged_in=false;
	private $_expire=0;

  public $name; # unique id of current user
  public $user;   # = {} user object
  public $location;   # = {} user's location object
	public $admin_rank = 0; # user's privilege rank 0 - 7
	public $admin_group = 'GUEST'; # user's privilege rank 0 - 7

  public static $errors = [];


  function __construct() {
    # start session if not already started
    if (session_status() == PHP_SESSION_NONE || session_id() == '') {  session_start();	}
    # check existing login
    $this->_checkLogin();
  }

  public function isLoggedIn() { return $this->_logged_in;  }
	public function login($user, int $remember=0) {
    $this->_expire = (int)$remember > \time() ? (int)$remember : \strtotime('35 min');
    \session_regenerate_id();
    if( \is_array($user) ){
      $obj = new \StdClass();
      foreach ($user as $key => $value) {
        if( !\is_int($key) ) $obj->$key = $value;
      }
      $user = $obj;
    }
    $this->admin_rank = $_SESSION['admin_rank'] = (
        \property_exists($user,'admin_rank')
      ) ? $user->admin_rank
        : 0;
    $this->admin_group = $_SESSION['admin_group'] = (
        \property_exists($user,'admin_group')
      ) ? $user->admin_group
        : "GUEST";
    $this->user = $_SESSION['user'] = $user;
    $this->name = $_SESSION['name'] = \property_exists($user,'uniqueid') ?
    $user->uniqueid : $this->name;
    $_SESSION['_expire'] = $this->_expire;
    try {
      $loc = new Location();
      $loc->city = !empty($_COOKIE['city']) ? $_COOKIE['city'] : $loc->city;
      $loc->latitude = !empty($_COOKIE['latitude']) ? $_COOKIE['latitude'] : $loc->latitude;
      $loc->longitude = !empty($_COOKIE['longitude']) ? $_COOKIE['longitude'] : $loc->longitude;
      $local = new \stdClass();
      $local->ip = $loc->ip;
      $local->city = $loc->city;
      $local->city_code = $loc->city_code;
      $local->state = $loc->state;
      $local->state_code = $loc->state_code;
      $local->country = $loc->country;
      $local->country_code = $loc->country_code;
      $local->currency_code = $loc->currency_code;
      $local->currency_symbol = $loc->currency_symbol;
      $local->latitude = $loc->latitude;
      $local->longitude = $loc->longitude;
      $this->location = $_SESSION['location'] = $local;
    } catch (\Exception $e) {
      $this->errors['login'][] = [0,256,$e->getMessage(),__FILE__,__LINE__];
    }
    $this->_logged_in = true;
	}
	public function logout(){
    if( $this->_logged_in ){
      if( isset($_SESSION['user']) ) unset($_SESSION['user']);
      if( isset($_SESSION['location']) ) unset($_SESSION['location']);
      if( isset($_SESSION['_expire']) ) unset($_SESSION['_expire']);
      if( isset($_SESSION['admin_rank']) ) unset($_SESSION['admin_rank']);
      if( isset($_SESSION['admin_group']) ) unset($_SESSION['admin_group']);
      if( isset($this->user) ) unset($this->user);
      if( isset($this->location) ) unset($this->location);

      $this->_expire = 0;
      $this->_logged_in = false;
    }
	}
  private function _checkLogin(){
		if(
          isset($_SESSION['user']) &&
          is_object($_SESSION['user']) &&
          isset($_SESSION['_expire']) &&
          (int)$_SESSION['_expire'] > time()
        ) {
			session_regenerate_id();
			$this->user = $_SESSION['user'];
			$this->name = $_SESSION['name'];
			$this->admin_rank = @(int)$_SESSION['admin_rank'];
			$this->admin_group = @$_SESSION['admin_group'];
			$this->_expire = (int)$_SESSION['_expire'];
      if( !empty($_SESSION['location']) && \gettype($_SESSION['location']) == "object" ){
        $this->location = $_SESSION['location'];
      }
			$this->_logged_in = true;
		}else{
      if( isset($_SESSION['user']) ) unset($_SESSION['user']);
      $this->name = !isset($this->name) ? "USER".time() : $this->name;
			unset($this->user);
			if(isset($this->_key)) unset($this->_key);
			$this->_expire = 0;
		}
	}
  public function relocate(){
    try {
      $loc = new Location();
      $loc->city = !empty($_COOKIE['city']) ? $_COOKIE['city'] : $loc->city;
      $loc->latitude = !empty($_COOKIE['latitude']) ? $_COOKIE['latitude'] : $loc->latitude;
      $loc->longitude = !empty($_COOKIE['longitude']) ? $_COOKIE['longitude'] : $loc->longitude;
      $this->location = $_SESSION['location'] = $loc;
      return true;
    } catch (\Exception $e) {
      $this->errors['relocate'][] = [0,256,$e->getMessage(),__FILE__,__LINE__];
      return false;
    }
  }
  public function setExpire( int $tym=0){
		if($tym > \time()){
			$this->_expire = $tym;
		}else{
			$this->_checkLogin();
		}
	}
  public function expiry(){ return $this->_expire; }
  public function createCSRFtoken(string $form, int $expiry=0){
    $data = new Data();
    $string = "{$form}jeSpegUtuxestAJUnAdephUhuvun";
    $token = $data->encodeEncrypt($string);
    $tym = $expiry > \time() ? $tym : \strtotime('45 min');
    $_SESSION['CSRF_token'][$form] = "{$token}::{$tym}";
    return $token;
  }
  public function isValidCSRFtoken(string $form,string $token,int $token_exp=0){
    $data = new Data();
    if( !empty($_SESSION['CSRF_token'][$form]) ){
      $token_exp = (int)$token_exp >0 ? (int)$token_exp : \time();
      $token_arr = \explode('::',$_SESSION['CSRF_token'][$form]);
      if( \count($token_arr) ===2 ){
        $string = "{$form}jeSpegUtuxestAJUnAdephUhuvun";
        $token_stored = $data->decodeDecrypt($token_arr[0]);
        $token_tym = (int)$token_arr[1];
        if( $string == $token_stored && $token_tym > $token_exp ){
          return true;
        }else{
          unset($_SESSION['CSRF_token']);
        }
      }
    }
    return false;
  }
  public function put($k,$v){
    if( $k && !empty($v) ){
      $_SESSION[$k] = $v;
    }
  }
  public function key(){ return $this->_key; }

}
