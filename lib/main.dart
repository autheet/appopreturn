import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:appopreturn/firebase_options.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:crypto/crypto.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );

  // Use the debug provider in debug mode, and the production providers in release mode.
  if (kDebugMode) {
    await FirebaseAppCheck.instance.activate(
      androidProvider: AndroidProvider.debug,
      appleProvider: AppleProvider.debug,
      webProvider: ReCaptchaV3Provider('6Lc61oArAAAAALykUAJkM-XD-vu8nwSPscHit4e2'),
    );
  } else {
    await FirebaseAppCheck.instance.activate(
      webProvider: ReCaptchaEnterpriseProvider('6Lc61oArAAAAALykUAJkM-XD-vu8nwSPscHit4e2'),
      androidProvider: AndroidProvider.playIntegrity,
      appleProvider: AppleProvider.appAttest,
    );
  }
  
  runApp(const AppOpReturn());
}

class AppOpReturn extends StatelessWidget {
  const AppOpReturn({super.key});

  @override
  Widget build(BuildContext context) {
    // Define the light theme based on the existing style
    final lightTheme = ThemeData(
      colorScheme: ColorScheme.fromSeed(
        seedColor: Colors.blue,
        brightness: Brightness.light,
      ),
      useMaterial3: true,
      scaffoldBackgroundColor: const Color(0xFFECEFF1),
    );

    // Define a corresponding dark theme
    final darkTheme = ThemeData(
      colorScheme: ColorScheme.fromSeed(
        seedColor: Colors.blue,
        brightness: Brightness.dark,
      ),
      useMaterial3: true,
      // Scaffold background will be dark by default with a dark color scheme
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
    Text('My Proofs Page (Not Implemented)'),
    Text('Settings Page (Not Implemented)'),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: <Widget>[
          NavigationRail(
            selectedIndex: _selectedIndex,
            onDestinationSelected: (int index) {
              setState(() {
                _selectedIndex = index;
              });
            },
            labelType: NavigationRailLabelType.all,
            leading: Image.asset('web/icons/icon.png', width: 40, height: 40),
            destinations: const <NavigationRailDestination>[
              NavigationRailDestination(
                icon: Icon(Icons.add_box_outlined),
                selectedIcon: Icon(Icons.add_box),
                label: Text('Create Proof'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.history_outlined),
                selectedIcon: Icon(Icons.history),
                label: Text('My Proofs'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.settings_outlined),
                selectedIcon: Icon(Icons.settings),
                label: Text('Settings'),
              ),
            ],
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(
            child: Column(
              children: [
                Expanded(
                  child: Center(
                    child: _widgetOptions.elementAt(_selectedIndex),
                  ),
                ),
                const Footer(),
              ],
            ),
          ),
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

class _CreateProofPageState extends State<CreateProofPage> with TickerProviderStateMixin {
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
      CurvedAnimation(parent: _breathingController, curve: Curves.easeInOut)
    );
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
    FilePickerResult? result = await FilePicker.platform.pickFiles(withData: true);
    if (result != null && result.files.single.bytes != null) {
      await _processData(result.files.single.name, result.files.single.bytes!);
    }
  }

  Future<void> _sendToBlockchain() async {
    if (_digest == null) return;
    setState(() { _loading = true; });
    try {
      final HttpsCallable callable =
          FirebaseFunctions.instance.httpsCallable('process_appopreturn_request_free');
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
              opacity: _digest != null ? 0.05 : 0.0, // Fades in when there's a result
              child: ScaleTransition(
                scale: _breathingAnimation,
                child: const Icon(Icons.fingerprint, size: 250, color: Colors.blueAccent),
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
      return const Padding(
        key: ValueKey('loading'),
        padding: EdgeInsets.symmetric(vertical: 60.0),
        child: CircularProgressIndicator(),
      );
    }
    if (_digest != null) {
      return _buildResultWidgets(key: const ValueKey('results'));
    }
    return _buildInitialWidgets(key: const ValueKey('initial'));
  }

   Widget _buildInitialWidgets({required Key key}) {
    final isDesktop = !kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux);
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
        SelectableText('Source: $_fileName', style: const TextStyle(fontWeight: FontWeight.bold)),
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
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.green),
          ),
          const SizedBox(height: 8),
          CopyableText(
            label: 'Your proof is permanently recorded. Here is the Transaction ID:',
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

class Footer extends StatelessWidget {
  const Footer({super.key});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(8.0),
      child: TextButton(
        onPressed: () => launchUrl(Uri.parse('privacy_en.html')),
        child: const Text('Privacy Policy'),
      ),
    );
  }
}