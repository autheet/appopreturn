import 'dart:typed_data';

import 'package:appopreturn/firebase_options.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:crypto/crypto.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:receive_sharing_intent/receive_sharing_intent.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  runApp(const AppOpReturn());
}

class AppOpReturn extends StatelessWidget {
  const AppOpReturn({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Apreturn',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Apreturn'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String? _fileName;
  String? _digest;
  String? _transactionId;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    // The following is for handling files shared from other apps on mobile
    ReceiveSharingIntent.instance.getInitialMedia().then((List<SharedMediaFile> value) {
      if (value.isNotEmpty) {
        // This logic is mobile-specific and requires dart:io.
        // For this web-focused app, we'll rely on FilePicker and DropTarget.
      }
    });

    ReceiveSharingIntent.instance.getMediaStream().listen((List<SharedMediaFile> value) {
      if (value.isNotEmpty) {
        // See note above.
      }
    }, onError: (err) {
      print("getIntentDataStream error: $err");
    });
  }

  Future<void> _processFile(String name, Uint8List bytes) async {
    setState(() {
      _fileName = name;
      _loading = true;
      _digest = null;
      _transactionId = null;
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

    setState(() {
      _loading = true;
    });

    try {
      // Correctly call the cloud function for free users
      final HttpsCallable callable =
          FirebaseFunctions.instance.httpsCallable('process_appopreturn_request_free');
      final result = await callable.call(<String, dynamic>{
        'digest': _digest,
      });
      setState(() {
        _transactionId = result.data['transaction_id'];
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
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          if (_fileName != null)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: _reset,
              tooltip: 'Start Over',
            ),
        ],
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              if (_digest == null) ...[
                const Icon(Icons.fingerprint, size: 60, color: Colors.blue),
                const SizedBox(height: 20),
                const Text(
                  'Apreturn',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 10),
                const Text(
                  'Proof you had an idea first by creating a timestamped digest on the blockchain.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 16),
                ),
                const SizedBox(height: 30),
                DropTarget(
                  onDragDone: (details) async {
                    if (details.files.isNotEmpty) {
                      final file = details.files.first;
                      await _processFile(file.name, await file.readAsBytes());
                    }
                  },
                  child: Container(
                    height: 200,
                    width: double.infinity,
                    constraints: const BoxConstraints(maxWidth: 500),
                    decoration: BoxDecoration(
                      border: Border.all(color: Colors.grey.shade400, width: 2),
                      borderRadius: BorderRadius.circular(12),
                      color: Colors.grey.shade50,
                    ),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Text('Drop your file here', style: TextStyle(fontSize: 18, color: Colors.grey)),
                        const SizedBox(height: 15),
                        const Text('or', style: TextStyle(color: Colors.grey)),
                        const SizedBox(height: 15),
                        ElevatedButton.icon(
                          onPressed: _selectFile,
                          icon: const Icon(Icons.upload_file),
                          label: const Text('Select File'),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
              if (_loading) const Padding(
                padding: EdgeInsets.all(20.0),
                child: CircularProgressIndicator(),
              ),
              if (_digest != null && !_loading) ...[
                Card(
                  elevation: 2,
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Text('File: $_fileName', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                        const SizedBox(height: 15),
                        const Text("Your file's unique digest:", style: TextStyle(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 5),
                        SelectableText(
                          _digest!,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 14, backgroundColor: Colors.black12),
                        ),
                        const SizedBox(height: 20),
                        const Text(
                          'This digest is a cryptographic fingerprint of your file. To later prove you had the file, you must keep the file and this digest.',
                          style: TextStyle(fontStyle: FontStyle.italic, color: Colors.black54),
                        ),
                        const SizedBox(height: 20),
                        const Divider(),
                        const SizedBox(height: 10),
                        const Text(
                          'Ready to prove it?',
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 10),
                        const Text(
                          'For free, we will send this digest to the Bitcoin testnet4 blockchain. This creates a permanent, public timestamp.',
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 20),
                        if (_transactionId == null)
                          Center(
                            child: ElevatedButton(
                              onPressed: _sendToBlockchain,
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.blue,
                                foregroundColor: Colors.white,
                                padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 15),
                              ),
                              child: const Text('Send to Blockchain'),
                            ),
                          ),
                        if (_transactionId != null) ...[
                          const SizedBox(height: 10),
                          const Text(
                            'Success! Here is your Transaction ID:',
                            style: TextStyle(fontWeight: FontWeight.bold, color: Colors.green),
                            textAlign: TextAlign.center,
                          ),
                          SelectableText(
                            _transactionId!,
                            textAlign: TextAlign.center,
                            style: const TextStyle(fontFamily: 'monospace', fontSize: 14)
                          ),
                        ]
                      ],
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
