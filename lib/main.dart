import 'dart:convert';
import 'dart:typed_data';

import 'package:appopreturn/firebase_options.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:crypto/crypto.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package.flutter/material.dart';
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
      title: 'AppOpReturn',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
      ),
      home: const MyHomePage(title: 'AppOpReturn'),
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
  String? _filePath;
  String? _digest;
  String? _transactionId;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    // Handle file sharing from other apps
    ReceiveSharingIntent.getInitialMedia().then((List<SharedMediaFile> value) {
      if (value.isNotEmpty) {
        setState(() {
          _filePath = value.first.path;
          _calculateDigest();
        });
      }
    });

    ReceiveSharingIntent.getMediaStream().listen((List<SharedMediaFile> value) {
      if (value.isNotEmpty) {
        setState(() {
          _filePath = value.first.path;
          _calculateDigest();
        });
      }
    }, onError: (err) {
      print("getIntentDataStream error: $err");
    });
  }

  Future<void> _selectFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      setState(() {
        _filePath = result.files.single.path;
        _calculateDigest();
      });
    }
  }

  Future<void> _calculateDigest() async {
    if (_filePath == null) return;

    setState(() {
      _loading = true;
    });

    try {
      final fileBytes = await FilePicker.platform
          .pickFiles(withData: true, type: FileType.any);
      if (fileBytes != null) {
        final bytes = fileBytes.files.single.bytes!;
        final digest = sha256.convert(bytes);
        setState(() {
          _digest = digest.toString();
        });
      }
    } catch (e) {
      print('Error calculating digest: $e');
    } finally {
      setState(() {
        _loading = false;
      });
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
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'Select a file to create a digest and store it on the blockchain.',
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _selectFile,
              child: const Text('Select File'),
            ),
            const SizedBox(height: 20),
            DropTarget(
              onDragDone: (details) {
                setState(() {
                  _filePath = details.files.first.path;
                  _calculateDigest();
                });
              },
              child: Container(
                height: 200,
                width: 300,
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.grey),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Center(
                  child: Text('Or drop a file here'),
                ),
              ),
            ),
            if (_filePath != null) ...[
              const SizedBox(height: 20),
              Text('Selected file: $_filePath'),
            ],
            if (_digest != null) ...[
              const SizedBox(height: 20),
              Text('Digest: $_digest'),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: _sendToBlockchain,
                child: const Text('Send to Blockchain'),
              ),
            ],
            if (_loading) ...[
              const SizedBox(height: 20),
              const CircularProgressIndicator(),
            ],
            if (_transactionId != null) ...[
              const SizedBox(height: 20),
              Text('Transaction ID: $_transactionId'),
            ],
          ],
        ),
      ),
    );
  }
}
