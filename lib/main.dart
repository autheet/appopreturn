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
        // Note: This provides a file path. Reading bytes from a path requires
        // dart:io, which is not available on web. This logic is mobile-specific.
        // For simplicity, we'll focus on the primary file drop/pick functionality.
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
      final HttpsCallable callable =
          FirebaseFunctions.instance.httpsCallable('process_apreturn_request');
      final result = await callable.call(<String, dynamic>{
        'digest': _digest,
        'is_paying_user': false, // Change this based on your payment logic
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
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
              const SizedBox(height: 30),
              if (_loading) const CircularProgressIndicator(),
              if (_digest != null) ...[
                Card(
                  elevation: 2,
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('File: $_fileName', style: const TextStyle(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 10),
                        const Text('SHA-256 Digest:', style: TextStyle(fontWeight: FontWeight.bold)),
                        const SizedBox(height: 5),
                        SelectableText(_digest!, style: const TextStyle(fontFamily: 'monospace', fontSize: 14)),
                        const SizedBox(height: 20),
                        const Text(
                          'Keep your original file safe and unchanged. This digest is your proof of existence at this point in time.',
                          style: TextStyle(fontStyle: FontStyle.italic, color: Colors.black54),
                        ),
                        const SizedBox(height: 20),
                        Center(
                          child: ElevatedButton(
                            onPressed: _sendToBlockchain,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.blue,
                              foregroundColor: Colors.white,
                              padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 15),
                            ),
                            child: const Text('Send digest to Blockchain'),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
              if (_transactionId != null) ...[
                const SizedBox(height: 20),
                const Text('Success! Transaction sent:', style: TextStyle(fontWeight: FontWeight.bold)),
                SelectableText(_transactionId!),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
