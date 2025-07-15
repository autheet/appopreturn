import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_markdown/flutter_markdown.dart';

class HelpPage extends StatelessWidget {
  const HelpPage({super.key});

  Future<String> _loadReadme() async {
    return await rootBundle.loadString('README.md');
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<String>(
      future: _loadReadme(),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const Center(child: CircularProgressIndicator());
        }
        if (snapshot.hasError) {
          return Center(child: Text('Error loading help content: ${snapshot.error}'));
        }
        if (!snapshot.hasData || snapshot.data!.isEmpty) {
          return const Center(child: Text('Help content is not available.'));
        }

        return SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: MarkdownBody(
            data: snapshot.data!,
            onTapLink: (text, href, title) {
              // You can add link handling here if needed
            },
          ),
        );
      },
    );
  }
}
