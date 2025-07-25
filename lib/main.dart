import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:appopreturn/firebase_options.dart';
import 'package:appopreturn/help_page.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:crypto/crypto.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:flutter/services.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher.dart';

// Get the reCAPTCHA site key from the environment.
// The key is passed in during the build process using the --dart-define flag.
const reCaptchaEnterpriseSiteKey = String.fromEnvironment('RECAPTCHA_ENTERPRISE_SITE_KEY');

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // On release builds, check if the reCAPTCHA key is provided.
  if (!kDebugMode && reCaptchaEnterpriseSiteKey.isEmpty) {
    throw Exception(
        'RECAPTCHA_ENTERPRISE_SITE_KEY is not set. Please provide it during the build process using --dart-define=RECAPTCHA_ENTERPRISE_SITE_KEY=YOUR_KEY');
  }

  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );


  // Define providers based on the build mode to keep it clean.
  final appleProvider = kDebugMode ? AppleProvider.debug : AppleProvider.appAttest;
  final androidProvider = kDebugMode ? AndroidProvider.debug : AndroidProvider.playIntegrity;

  // Activate App Check with the correct providers.
  await FirebaseAppCheck.instance.activate(
    webProvider: ReCaptchaEnterpriseProvider(reCaptchaEnterpriseSiteKey),
    androidProvider: androidProvider,
    appleProvider: appleProvider,
  );

  // You can still listen for the debug token when in debug mode.
  if (kDebugMode) {
    FirebaseAppCheck.instance.onTokenChange.listen((token) {
      if (token != null) {
        print('App Check debug token for testing: $token');
      }
    });
  }


  runApp(const AppOpReturn());
}

class AppOpReturn extends StatelessWidget {
  const AppOpReturn({super.key});

  @override
  Widget build(BuildContext context) {
    const seedColor = Color(0xFF0D47A1); // Deep Blue

    // Define the light theme based on the seed color
    final lightTheme = ThemeData(
      colorScheme: ColorScheme.fromSeed(
        seedColor: seedColor,
        brightness: Brightness.light,
      ),
      useMaterial3: true,
    );

    // Define a corresponding dark theme
    final darkTheme = ThemeData(
      colorScheme: ColorScheme.fromSeed(
        seedColor: seedColor,
        brightness: Brightness.dark,
      ),
      useMaterial3: true,
    );

    return MaterialApp(
      title: 'AppOpReturn',
      theme: lightTheme,
      darkTheme: darkTheme,
      themeMode: ThemeMode.system, // This enables auto-switching
      home: const AppShell(),
    );
  }
}

class AppShell extends StatefulWidget {
  const AppShell({super.key});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  int _selectedIndex = 0;

  static const List<Widget> _widgetOptions = <Widget>[
    CreateProofPage(),
    HelpPage(),
    SettingsPage(),
  ];

  Future<void> _launchPrivacyPolicy() async {
    final uri = Uri.parse('https://appopreturn.autheet.com/privacy_en.html');
    if (!await launchUrl(uri, webOnlyWindowName: '_blank')) {
      print('Could not launch $uri');
    }
  }

  void _onItemTapped(int index) {
    // The "Privacy" item is at index 2
    if (index == 2) {
      _launchPrivacyPolicy();
      // Do not change the selected index, as this is an action, not a page change.
    } else {
      setState(() {
        _selectedIndex = index;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    // Map the selected index to the correct widget, skipping the action item.
    final pageIndex = _selectedIndex > 2 ? _selectedIndex - 1 : _selectedIndex;

    return LayoutBuilder(
      builder: (context, constraints) {
        const double navigationRailThreshold = 600;

        final destinations = [
          const NavigationRailDestination(
            icon: Icon(Icons.add_box_outlined),
            selectedIcon: Icon(Icons.add_box),
            label: Text('Create Proof'),
          ),
          const NavigationRailDestination(
            icon: Icon(Icons.help_outline),
            selectedIcon: Icon(Icons.help),
            label: Text('Help'),
          ),
          const NavigationRailDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: Text('Privacy'),
          ),
          const NavigationRailDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: Text('Settings'),
          ),
        ];

        if (constraints.maxWidth < navigationRailThreshold) {
          return Scaffold(
            body: Center(
              child: _widgetOptions.elementAt(pageIndex),
            ),
            bottomNavigationBar: BottomNavigationBar(
              type: BottomNavigationBarType.fixed,
              items: destinations.map((d) => BottomNavigationBarItem(icon: d.icon, activeIcon: d.selectedIcon, label: (d.label as Text).data)).toList(),
              currentIndex: _selectedIndex,
              onTap: _onItemTapped,
            ),
          );
        } else {
          return Scaffold(
            body: Row(
              children: <Widget>[
                NavigationRail(
                  selectedIndex: _selectedIndex,
                  onDestinationSelected: _onItemTapped,
                  labelType: NavigationRailLabelType.all,
                  leading: Image.asset('web/icons/icon.png', width: 40, height: 40),
                  destinations: destinations,
                ),
                const VerticalDivider(thickness: 1, width: 1),
                Expanded(
                  child: Center(
                    child: _widgetOptions.elementAt(pageIndex),
                  ),
                ),
              ],
            ),
          );
        }
      },
    );
  }
}

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  PackageInfo _packageInfo = PackageInfo(
    appName: 'Unknown',
    packageName: 'Unknown',
    version: 'Unknown',
    buildNumber: 'Unknown',
  );

  @override
  void initState() {
    super.initState();
    _initPackageInfo();
  }

  Future<void> _initPackageInfo() async {
    final info = await PackageInfo.fromPlatform();
    setState(() {
      _packageInfo = info;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: <Widget>[
          Text('App Version: ${_packageInfo.version}'),
          Text('Build Number: ${_packageInfo.buildNumber}'),
        ],
      ),
    );
  }
}

class CreateProofPage extends StatefulWidget {
  const CreateProofPage({super.key});

  @override
  State<CreateProofPage> createState() => _CreateProofPageState();
}

class _CreateProofPageState extends State<CreateProofPage>
    with TickerProviderStateMixin {
  String? _fileName;
  String? _digest;
  String? _transactionId;
  String? _network;
  bool _loading = false;

  late final AnimationController _breathingController;
  late final Animation<double> _breathingAnimation;

  @override
  void initState() {
    super.initState();
    _breathingController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _breathingAnimation = Tween<double>(begin: 1.0, end: 1.05).animate(
        CurvedAnimation(parent: _breathingController, curve: Curves.easeInOut));
  }

  @override
  void dispose() {
    _breathingController.dispose();
    super.dispose();
  }

  Future<void> _processData(String name, Uint8List bytes) async {
    setState(() {
      _fileName = name;
      _loading = true;
      _digest = null;
      _transactionId = null;
      _network = null;
    });

    try {
      final digest = sha256.convert(bytes);
      setState(() {
        _digest = digest.toString();
      });
    } catch (e) {
      print('Error calculating digest: $e');
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Future<void> _selectFile() async {
    FilePickerResult? result =
    await FilePicker.platform.pickFiles(withData: true);
    if (result != null && result.files.single.bytes != null) {
      await _processData(result.files.single.name, result.files.single.bytes!);
    }
  }

  Future<void> _sendToBlockchain() async {
    if (_digest == null) return;
    setState(() {
      _loading = true;
    });
    try {
      // Set a 180-second timeout for the callable function.
      final HttpsCallable callable = FirebaseFunctions.instance
          .httpsCallable(
        'process_appopreturn_request_free',
        options: HttpsCallableOptions(
          timeout: const Duration(seconds: 180),
        ),
      );
      final result = await callable.call(<String, dynamic>{'digest': _digest});
      setState(() {
        _transactionId = result.data['transaction_id'];
        _network = result.data['network'];
      });
    } catch (e) {
      print('Error sending to blockchain: $e');
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  void _reset() {
    setState(() {
      _fileName = null;
      _digest = null;
      _transactionId = null;
      _network = null;
      _loading = false;
    });
  }

  Future<void> _launchBlockchainExplorer() async {
    if (_transactionId == null || _network == null) return;

    String url;
    switch (_network) {
      case 'testnet3':
        url = 'https://mempool.space/testnet/tx/$_transactionId';
        break;
      case 'ethereum':
        url = 'https://etherscan.io/tx/$_transactionId';
        break;
      case 'sepolia':
        url = 'https://sepolia.etherscan.io/tx/$_transactionId';
        break;
      default:
        print('Unknown network: $_network');
        return;
    }

    final uri = Uri.parse(url);
    if (!await launchUrl(uri)) {
      print('Could not launch $url');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(maxWidth: 650),
      child: Card(
        elevation: 8.0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: Stack(
          alignment: Alignment.center,
          children: [
            // Animated Background Icon
            AnimatedOpacity(
              duration: const Duration(milliseconds: 500),
              opacity: _digest != null
                  ? 0.05
                  : 0.0, // Fades in when there's a result
              child: ScaleTransition(
                scale: _breathingAnimation,
                child: const Icon(Icons.fingerprint,
                    size: 250, color: Colors.blueAccent),
              ),
            ),
            // Main Content
            Padding(
              padding: const EdgeInsets.all(32.0),
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 300),
                child: _buildContent(),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildContent() {
    if (_loading) {
      return Padding(
        key: const ValueKey('loading'),
        padding: const EdgeInsets.all(32.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 24),
            Text(
              'Creating your transaction. This may take up to two minutes.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      );
    }
    if (_digest != null) {
      return _buildResultWidgets(key: const ValueKey('results'));
    }
    return _buildInitialWidgets(key: const ValueKey('initial'));
  }

  Widget _buildInitialWidgets({required Key key}) {
    final isDesktop =
        !kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux);
    final showDropZone = kIsWeb || isDesktop;
    final theme = Theme.of(context);

    Widget dropZoneContent = Container(
      height: 150,
      width: double.infinity,
      decoration: BoxDecoration(
        border: Border.all(color: theme.colorScheme.outline, width: 2),
        borderRadius: BorderRadius.circular(8),
        color: theme.colorScheme.surfaceVariant,
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          if (showDropZone) ...[
            const Text('Drop your file here'),
            const SizedBox(height: 10),
            const Text('or'),
            const SizedBox(height: 10),
          ] else ...[
            const Text('Select a file to begin'),
            const SizedBox(height: 16),
          ],
          ElevatedButton(
            onPressed: _selectFile,
            child: const Text('Select a File'),
          ),
        ],
      ),
    );

    return Column(
      key: key,
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.fingerprint, size: 50, color: Colors.blueAccent),
        const SizedBox(height: 16),
        const Text(
          'Create a Proof of Existence',
          style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 8),
        Text(
          'Select a file to generate a unique, timestamped digest on the blockchain.',
          textAlign: TextAlign.center,
          style: theme.textTheme.bodyLarge,
        ),
        const SizedBox(height: 24),
        if (showDropZone)
          DropTarget(
            onDragDone: (details) async {
              if (details.files.isNotEmpty) {
                final file = details.files.first;
                await _processData(file.name, await file.readAsBytes());
              }
            },
            child: dropZoneContent,
          )
        else
          dropZoneContent,
      ],
    );
  }

  Widget _buildResultWidgets({required Key key}) {
    final theme = Theme.of(context);
    final digestBackgroundColor = theme.brightness == Brightness.dark
        ? theme.colorScheme.surfaceVariant
        : const Color(0xFFECEFF1);

    return Column(
      key: key,
      mainAxisSize: MainAxisSize.min,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text(
              'Your Digital Proof',
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
            ),
            IconButton(
              icon: const Icon(Icons.close),
              onPressed: _reset,
              tooltip: 'Start Over',
            ),
          ],
        ),
        const SizedBox(height: 16),
        SelectableText('Source: $_fileName',
            style: const TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 10),
        CopyableText(
          label: "Your data's unique digest:",
          text: _digest!,
          textStyle: TextStyle(
            fontFamily: 'monospace',
            fontSize: 13,
            backgroundColor: digestBackgroundColor,
          ),
        ),
        const SizedBox(height: 16),
        if (_transactionId == null) ...[
          const Divider(height: 32),
          const Text(
            'Ready to notarize this proof on the blockchain?',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 16),
          ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            onPressed: _sendToBlockchain,
            icon: const Icon(Icons.security),
            label: const Text('Notarize'),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.orangeAccent,
              foregroundColor: Colors.white,
            ),
          ),
        ] else ...[
          const Divider(height: 32),
          const Text(
            'Success!',
            style: TextStyle(
                fontSize: 18, fontWeight: FontWeight.bold, color: Colors.green),
          ),
          const SizedBox(height:.8),
          CopyableText(
            label:
            'Your proof is permanently recorded. Here is the Transaction ID:',
            text: _transactionId!,
            textStyle: const TextStyle(fontFamily: 'monospace', fontSize: 13),
          ),
          const SizedBox(height: 8),
          SelectableText('Network: $_network'),
          const SizedBox(height: 16),
          TextButton.icon(
            onPressed: _launchBlockchainExplorer,
            icon: const Icon(Icons.open_in_new, size: 18),
            label: const Text('View Transaction on Blockchain Explorer'),
          ),
        ]
      ],
    );
  }
}

class CopyableText extends StatelessWidget {
  final String text;
  final String? label;
  final TextStyle? textStyle;

  const CopyableText({
    super.key,
    required this.text,
    this.label,
    this.textStyle,
  });

  @override
  Widget build(BuildContext context) {
    final defaultStyle = const TextStyle(fontFamily: 'monospace', fontSize: 13);
    final effectiveTextStyle = textStyle ?? defaultStyle;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (label != null) ...[
          Text(label!),
          const SizedBox(height: 5),
        ],
        Row(
          children: [
            Expanded(
              child: SelectableText(
                text,
                style: effectiveTextStyle,
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: const Icon(Icons.copy, size: 18),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: text));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Copied to clipboard'),
                    duration: Duration(seconds: 1),
                  ),
                );
              },
              tooltip: 'Copy',
            ),
          ],
        ),
      ],
    );
  }
}
