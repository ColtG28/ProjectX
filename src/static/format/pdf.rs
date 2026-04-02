pub fn suspicious_markers(bytes: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let markers = [
        ("/javascript", "/JavaScript"),
        ("/js", "/JS"),
        ("/openaction", "/OpenAction"),
        ("/launch", "/Launch"),
        ("/submitform", "/SubmitForm"),
        ("embeddedfile", "EmbeddedFile"),
        ("/aa", "/AA"),
        ("/richmedia", "/RichMedia"),
    ];

    markers
        .into_iter()
        .filter_map(|(needle, label)| text.contains(needle).then_some(label))
        .collect()
}

pub fn extract_javascript_fragments(
    bytes: &[u8],
    max_fragments: usize,
    max_fragment_bytes: usize,
) -> Vec<String> {
    let mut out = Vec::new();

    for marker in [b"/JavaScript".as_slice(), b"/JS".as_slice()] {
        for offset in find_all(bytes, marker).into_iter().take(max_fragments) {
            if let Some(script) = extract_literal_after(bytes, offset + marker.len()) {
                let mut script = script;
                script.truncate(max_fragment_bytes);
                if !script.trim().is_empty() && !out.contains(&script) {
                    out.push(script);
                }
            }
        }
    }

    out
}

pub fn extract_embedded_streams(
    bytes: &[u8],
    max_streams: usize,
    max_stream_bytes: usize,
) -> Vec<Vec<u8>> {
    let mut streams = Vec::new();

    for marker in [
        b"EmbeddedFile".as_slice(),
        b"/JavaScript".as_slice(),
        b"/JS".as_slice(),
    ] {
        for offset in find_all(bytes, marker).into_iter().take(max_streams) {
            if let Some(stream) = extract_stream_after(bytes, offset, max_stream_bytes) {
                if !stream.is_empty() {
                    streams.push(stream);
                }
            }
            if streams.len() >= max_streams {
                return streams;
            }
        }
    }

    streams
}

fn find_all(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn extract_literal_after(bytes: &[u8], start: usize) -> Option<String> {
    let search = &bytes[start..bytes.len().min(start + 2048)];
    let open = search.iter().position(|byte| *byte == b'(')?;
    let literal_start = start + open + 1;

    let mut cursor = literal_start;
    let mut depth = 1usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor = cursor.saturating_add(2),
            b'(' => {
                depth += 1;
                cursor += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let literal = &bytes[literal_start..cursor];
                    return Some(String::from_utf8_lossy(literal).to_string());
                }
                cursor += 1;
            }
            _ => cursor += 1,
        }
    }
    None
}

fn extract_stream_after(bytes: &[u8], start: usize, max_stream_bytes: usize) -> Option<Vec<u8>> {
    let search_end = bytes.len().min(start + 8192);
    let search = &bytes[start..search_end];
    let stream_offset = search.windows(6).position(|window| window == b"stream")?;
    let mut data_start = start + stream_offset + 6;

    if bytes.get(data_start) == Some(&b'\r') {
        data_start += 1;
    }
    if bytes.get(data_start) == Some(&b'\n') {
        data_start += 1;
    }

    let stream_end = bytes[data_start..]
        .windows(9)
        .position(|window| window == b"endstream")?;
    let data_end = data_start + stream_end;
    let mut data = bytes[data_start..data_end].to_vec();
    data.truncate(max_stream_bytes);
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::extract_javascript_fragments;

    #[test]
    fn extracts_pdf_javascript_literals() {
        let pdf = br#"%PDF-1.7
1 0 obj
<< /Names [(OpenAction) << /S /JavaScript /JS (app.alert("hi")) >>] >>
endobj
"#;
        let fragments = extract_javascript_fragments(pdf, 4, 4096);
        assert!(fragments
            .iter()
            .any(|fragment| fragment.contains("app.alert")));
    }
}
