import 'dart:async';
import 'dart:convert';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/models/ab_model.dart';
import 'package:get/get.dart';
import 'package:url_launcher/url_launcher.dart';

import '../common.dart';
import '../utils/http_service.dart' as http;
import 'model.dart';
import 'platform_model.dart';

bool refreshingUser = false;
const _kAutoOidcFlagKey = 'auto_oidc_login_status';
const _kAutoOidcMaxTicks = 120;

class UserModel {
  final RxString userName = ''.obs;
  final RxBool isAdmin = false.obs;
  final RxString networkError = ''.obs;
  bool get isLogin => userName.isNotEmpty;
  WeakReference<FFI> parent;
  Timer? _autoOidcTimer;
  bool _autoOidcInProgress = false;
  int _autoOidcTick = 0;
  String _autoOidcLastUrl = '';

  UserModel(this.parent) {
    userName.listen((p0) {
      // When user name becomes empty, show login button
      // When user name becomes non-empty:
      //  For _updateLocalUserInfo, network error will be set later
      //  For login success, should clear network error
      networkError.value = '';
    });
  }

  void refreshCurrentUser() async {
    if (bind.isDisableAccount()) return;
    networkError.value = '';
    final token = bind.mainGetLocalOption(key: 'access_token');
    if (token == '') {
      await _maybeAutoOidcLogin();
      await updateOtherModels();
      return;
    }
    _updateLocalUserInfo();
    final url = await bind.mainGetApiServer();
    final body = {
      'id': await bind.mainGetMyId(),
      'uuid': await bind.mainGetUuid()
    };
    if (refreshingUser) return;
    try {
      refreshingUser = true;
      final http.Response response;
      try {
        response = await http.post(Uri.parse('$url/api/currentUser'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer $token'
            },
            body: json.encode(body));
      } catch (e) {
        networkError.value = e.toString();
        rethrow;
      }
      refreshingUser = false;
      final status = response.statusCode;
      if (status == 401 || status == 400) {
        reset(resetOther: status == 401);
        return;
      }
      final data = json.decode(decode_http_response(response));
      final error = data['error'];
      if (error != null) {
        throw error;
      }

      final user = UserPayload.fromJson(data);
      _parseAndUpdateUser(user);
    } catch (e) {
      debugPrint('Failed to refreshCurrentUser: $e');
    } finally {
      refreshingUser = false;
      await updateOtherModels();
    }
  }

  static Map<String, dynamic>? getLocalUserInfo() {
    final userInfo = bind.mainGetLocalOption(key: 'user_info');
    if (userInfo == '') {
      return null;
    }
    try {
      return json.decode(userInfo);
    } catch (e) {
      debugPrint('Failed to get local user info "$userInfo": $e');
    }
    return null;
  }

  _updateLocalUserInfo() {
    final userInfo = getLocalUserInfo();
    if (userInfo != null) {
      userName.value = userInfo['name'];
    }
  }

  Future<void> reset({bool resetOther = false}) async {
    await bind.mainSetLocalOption(key: 'access_token', value: '');
    await bind.mainSetLocalOption(key: 'user_info', value: '');
    if (resetOther) {
      await gFFI.abModel.reset();
      await gFFI.groupModel.reset();
    }
    userName.value = '';
  }

  _parseAndUpdateUser(UserPayload user) {
    userName.value = user.name;
    isAdmin.value = user.isAdmin;
    bind.mainSetLocalOption(key: 'user_info', value: jsonEncode(user));
    if (isWeb) {
      // ugly here, tmp solution
      bind.mainSetLocalOption(key: 'verifier', value: user.verifier ?? '');
    }
  }

  // update ab and group status
  static Future<void> updateOtherModels() async {
    await Future.wait([
      gFFI.abModel.pullAb(force: ForcePullAb.listAndCurrent, quiet: false),
      gFFI.groupModel.pull()
    ]);
  }

  Future<void> logOut({String? apiServer}) async {
    final tag = gFFI.dialogManager.showLoading(translate('Waiting'));
    try {
      final url = apiServer ?? await bind.mainGetApiServer();
      final authHeaders = getHttpHeaders();
      authHeaders['Content-Type'] = "application/json";
      await http
          .post(Uri.parse('$url/api/logout'),
              body: jsonEncode({
                'id': await bind.mainGetMyId(),
                'uuid': await bind.mainGetUuid(),
              }),
              headers: authHeaders)
          .timeout(Duration(seconds: 2));
    } catch (e) {
      debugPrint("request /api/logout failed: err=$e");
    } finally {
      await reset(resetOther: true);
      gFFI.dialogManager.dismissByTag(tag);
    }
  }

  /// throw [RequestException]
  Future<LoginResponse> login(LoginRequest loginRequest) async {
    final url = await bind.mainGetApiServer();
    final resp = await http.post(Uri.parse('$url/api/login'),
        body: jsonEncode(loginRequest.toJson()));

    final Map<String, dynamic> body;
    try {
      body = jsonDecode(decode_http_response(resp));
    } catch (e) {
      debugPrint("login: jsonDecode resp body failed: ${e.toString()}");
      if (resp.statusCode != 200) {
        BotToast.showText(
            contentColor: Colors.red, text: 'HTTP ${resp.statusCode}');
      }
      rethrow;
    }
    if (resp.statusCode != 200) {
      throw RequestException(resp.statusCode, body['error'] ?? '');
    }
    if (body['error'] != null) {
      throw RequestException(0, body['error']);
    }

    return getLoginResponseFromAuthBody(body);
  }

  LoginResponse getLoginResponseFromAuthBody(Map<String, dynamic> body) {
    final LoginResponse loginResponse;
    try {
      loginResponse = LoginResponse.fromJson(body);
    } catch (e) {
      debugPrint("login: jsonDecode LoginResponse failed: ${e.toString()}");
      rethrow;
    }

    final isLogInDone = loginResponse.type == HttpType.kAuthResTypeToken &&
        loginResponse.access_token != null;
    if (isLogInDone && loginResponse.user != null) {
      _parseAndUpdateUser(loginResponse.user!);
    }

    return loginResponse;
  }

  static Future<List<dynamic>> queryOidcLoginOptions() async {
    try {
      final url = await bind.mainGetApiServer();
      if (url.trim().isEmpty) return [];
      final resp = await http.get(Uri.parse('$url/api/login-options'));
      final List<String> ops = [];
      for (final item in jsonDecode(resp.body)) {
        ops.add(item as String);
      }
      for (final item in ops) {
        if (item.startsWith('common-oidc/')) {
          return jsonDecode(item.substring('common-oidc/'.length));
        }
      }
      return ops
          .where((item) => item.startsWith('oidc/'))
          .map((item) => {'name': item.substring('oidc/'.length)})
          .toList();
    } catch (e) {
      debugPrint(
          "queryOidcLoginOptions: jsonDecode resp body failed: ${e.toString()}");
      return [];
    }
  }

  Future<void> _maybeAutoOidcLogin() async {
    if (!isDesktop || !isWindows) {
      _logAutoOidc(
          'Skip auto OIDC: not desktop/windows (desktop=$isDesktop, windows=$isWindows)');
      return;
    }
    if (_autoOidcInProgress) {
      _logAutoOidc('Skip auto OIDC: already in progress');
      return;
    }
    if (!bind.mainIsInstalled()) {
      _logAutoOidc('Skip auto OIDC: mainIsInstalled() returned false');
      return;
    }
    if (bind.mainGetLocalOption(key: 'access_token').isNotEmpty) {
      _logAutoOidc('Skip auto OIDC: access_token already present');
      return;
    }
    final status = bind.mainGetLocalOption(key: _kAutoOidcFlagKey);
    if (status == 'done') {
      _logAutoOidc('Skip auto OIDC: status already done');
      return;
    }

    final options = await queryOidcLoginOptions();
    _logAutoOidc(
        'Queried login options: ${options.map((e) => e.toString()).toList()}');
    if (options.isEmpty) {
      _logAutoOidc('Skip auto OIDC: no OIDC providers');
      return;
    }

    final oidcOptions = options.whereType<Map>().where((item) {
      final name = item['name'];
      if (name is! String || name.isEmpty) {
        return false;
      }
      final lower = name.toLowerCase();
      return lower != 'users/password' && lower != 'webauth';
    }).toList();

    if (oidcOptions.isEmpty) {
      _logAutoOidc('Skip auto OIDC: no usable OIDC providers found');
      return;
    }

    if (oidcOptions.length > 1) {
      _logAutoOidc(
          'Skip auto OIDC: multiple usable OIDC providers, count=${oidcOptions.length}');
      return;
    }

    final op = oidcOptions.first['name'].toString();
    if (op.isEmpty) {
      _logAutoOidc('Skip auto OIDC: provider name empty');
      return;
    }

    _autoOidcInProgress = true;
    _autoOidcLastUrl = '';
    _autoOidcTick = 0;
    await bind.mainSetLocalOption(key: _kAutoOidcFlagKey, value: 'pending');
    try {
      await bind.mainAccountAuth(op: op, rememberMe: true);
      _logAutoOidc('Started auto OIDC with provider "$op"');
    } catch (e) {
      _logAutoOidc('Auto OIDC login start failed: $e');
      _autoOidcInProgress = false;
      return;
    }
    _autoOidcTimer?.cancel();
    _autoOidcTimer = Timer.periodic(
        const Duration(seconds: 1), (_) => _pollAutoOidcResult());
  }

  void _stopAutoOidcTimer() {
    _autoOidcTimer?.cancel();
    _autoOidcTimer = null;
    _autoOidcInProgress = false;
  }

  void _pollAutoOidcResult() {
    bind.mainAccountAuthResult().then((result) async {
      if (!_autoOidcInProgress) {
        _logAutoOidc('Polling stopped: progress flag cleared');
        _stopAutoOidcTimer();
        return;
      }
      if (result.isEmpty) {
        _autoOidcTick++;
        if (_autoOidcTick == 1 || _autoOidcTick % 10 == 0) {
          _logAutoOidc('Waiting for OIDC auth result... tick=$_autoOidcTick');
        }
        if (_autoOidcTick > _kAutoOidcMaxTicks) {
          await bind.mainSetLocalOption(
              key: _kAutoOidcFlagKey, value: 'timeout');
          _logAutoOidc('Auto OIDC timed out after $_autoOidcTick seconds');
          _stopAutoOidcTimer();
        }
        return;
      }
      Map<String, dynamic>? resultMap;
      try {
        resultMap = jsonDecode(result) as Map<String, dynamic>;
      } catch (e) {
        _logAutoOidc('Failed to decode oidc auth result: $e');
        return;
      }
      final url = resultMap?['url'];
      if (url is String && url.isNotEmpty && _autoOidcLastUrl != url) {
        try {
          await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
        } catch (e) {
          _logAutoOidc('Failed to launch oidc url: $e');
        }
        _autoOidcLastUrl = url;
        _logAutoOidc('Opened browser for URL: $url');
      }
      final failedMsg = (resultMap?['failed_msg'] as String?) ?? '';
      final authBody = resultMap?['auth_body'];
      if (authBody is Map<String, dynamic>) {
        await _completeAutoOidcLogin(authBody);
        return;
      }
      if (failedMsg.isNotEmpty) {
        await bind.mainSetLocalOption(key: _kAutoOidcFlagKey, value: 'failed');
        _logAutoOidc('Auto OIDC failed: $failedMsg');
        _stopAutoOidcTimer();
      } else {
        _autoOidcTick++;
        if (_autoOidcTick > _kAutoOidcMaxTicks) {
          await bind.mainSetLocalOption(
              key: _kAutoOidcFlagKey, value: 'timeout');
          _logAutoOidc(
              'Auto OIDC timed out after $_autoOidcTick seconds (no auth body)');
          _stopAutoOidcTimer();
        }
      }
    }).catchError((e) {
      _logAutoOidc('Auto OIDC login polling error: $e');
    });
  }

  Future<void> _completeAutoOidcLogin(Map<String, dynamic> authBody) async {
    _stopAutoOidcTimer();
    await bind.mainSetLocalOption(key: _kAutoOidcFlagKey, value: 'done');
    try {
      final resp = getLoginResponseFromAuthBody(authBody);
      if (resp.type == HttpType.kAuthResTypeToken &&
          resp.access_token != null) {
        await bind.mainSetLocalOption(
            key: 'access_token', value: resp.access_token!);
        await bind.mainSetLocalOption(
            key: 'user_info', value: jsonEncode(resp.user ?? {}));
        _logAutoOidc('Auto OIDC login succeeded, token stored');
      }
    } catch (e) {
      _logAutoOidc('Failed to parse auto oidc login response: $e');
    }
    Future.microtask(() => refreshCurrentUser());
  }

  void _logAutoOidc(String message) {
    final ts = DateTime.now().toIso8601String();
    try {
      bind.mainSetLocalOption(key: '__auto_oidc_log', value: '[$ts] $message');
    } catch (e) {
      debugPrint('Auto OIDC logging failed: $e - original message: $message');
    }
  }
}
