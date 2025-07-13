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
import 'package:receive_sharing_intent/receive_sharing_intent.dart';
import 'package:url_launcher/url_launcher.dart';
// TODO: copy text possibility, privacy policy, sharing intent handling on mobiles.
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
    return MaterialApp(
      title: 'AppOpReturn',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFECEFF1),
      ),
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

class _CreateProofPageState extends State<CreateProofPage> {
  String? _fileName;
  String? _digest;
  String? _transactionId;
  String? _network;
  bool _loading = false;

  Future<void> _processFile(String name, Uint8List bytes) async {
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
      await _processFile(result.files.single.name, result.files.single.bytes!);
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

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(maxWidth: 500),
      child: Card(
        elevation: 8.0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: Padding(
          padding: const EdgeInsets.all(32.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              if (_digest == null) ..._buildInitialWidgets(),
              if (_loading) const Padding(
                padding: EdgeInsets.symmetric(vertical: 60.0),
                child: CircularProgressIndicator(),
              ),
              if (_digest != null && !_loading) ..._buildResultWidgets(),
            ],
          ),
        ),
      ),
    );
  }

   List<Widget> _buildInitialWidgets() {
    return [
      const Icon(Icons.fingerprint, size: 50, color: Colors.blueAccent),
      const SizedBox(height: 16),
      const Text(
        'Create a Proof of Existence',
        style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
      ),
      const SizedBox(height: 8),
      const Text(
        'Select a file to generate a unique, timestamped digest on the blockchain.',
        textAlign: TextAlign.center,
        style: TextStyle(fontSize: 16, color: Colors.black54),
      ),
      const SizedBox(height: 24),
      DropTarget(
        onDragDone: (details) async {
          if (details.files.isNotEmpty) {
            final file = details.files.first;
            await _processFile(file.name, await file.readAsBytes());
          }
        },
        child: Container(
          height: 150,
          width: double.infinity,
          decoration: BoxDecoration(
            border: Border.all(color: Colors.grey.shade300, width: 2),
            borderRadius: BorderRadius.circular(8),
            color: Colors.grey.shade50,
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text('Drop your file here'),
              const SizedBox(height: 10),
              const Text('or'),
              const SizedBox(height: 10),
              ElevatedButton(
                onPressed: _selectFile,
                child: const Text('Select a File'),
              ),
            ],
          ),
        ),
      ),
    ];
  }

  List<Widget> _buildResultWidgets() {
    return [
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
      SelectableText('File: $_fileName', style: const TextStyle(fontWeight: FontWeight.bold)),
      const SizedBox(height: 10),
      const Text("Your file's unique digest:"),
      const SizedBox(height: 5),
      SelectableText(
        _digest!,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 13, backgroundColor: Color(0xFFECEFF1)),
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
        const Text('Your proof is permanently recorded. Here is the Transaction ID:'),
        const SizedBox(height: 5),
        SelectableText(
          _transactionId!,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
        ),
        const SizedBox(height: 8),
        SelectableText('Network: $_network'),
      ]
    ];
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
