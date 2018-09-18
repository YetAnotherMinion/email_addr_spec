// Copyright 2018 Th!nk Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// The MIT License (MIT)
//
// Copyright (c) 2018 Th!nk Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

mod grammar {
    #[derive(Debug, PartialEq)]
    pub enum AST<'input> {
        QuotedString(Vec<AST<'input>>),
        QuotedPair(&'input str),
        Comment(Vec<AST<'input>>),
        WhiteSpace(&'input str),
        Fold(&'input str),
        Atom(&'input str),
    }

    pub mod rfc5322 {
        use super::AST;
        include!(concat!(env!("OUT_DIR"), "/email_rfc5322_grammar.rs"));
    }
}

pub const MAX_LOCAL_PART_LENGTH: usize = 63;
pub const MAX_DOMAIN_LENGTH: usize = 255;

/// Strip comments from email
pub fn canonicalize_rfc5322_email(s: &str) -> Result<String, ()> {
    // max length for rfc5622 is 63 bytes for local part, 255 bytes for domain part
    if s.len() > (MAX_LOCAL_PART_LENGTH + 1 + MAX_DOMAIN_LENGTH) {
        return Err(());
    }
    let (local_part, domain) = grammar::rfc5322::addr_spec(s).map_err(|_| ())?;

    let mut buffer = String::with_capacity(s.len());

    let keep_whitespace = false;
    let keep_comments = false;
    let keep_fold = false;
    write_to(&mut buffer, &local_part, keep_whitespace, keep_comments, keep_fold);

    let local_part_length = buffer.len();
    if local_part_length > MAX_LOCAL_PART_LENGTH {
        return Err(());
    }
    buffer.push('@');

    let keep_whitespace = false;
    let keep_comments = false;
    let keep_fold = false;
    write_to(&mut buffer, &domain, keep_whitespace, keep_comments, keep_fold);

    let domain_length = buffer.len() - local_part_length - 1;
    if domain_length > MAX_DOMAIN_LENGTH {
        return Err(());
    }
    // Remove trailing and leading whitespace
    Ok(buffer.trim().to_owned())
}

// Write a canonical version. This means quoted pairs will be simplified if they are in visible
// range
fn write_to<'input>(
    buffer: &mut String,
    nodes: &[grammar::AST<'input>],
    keep_whitespace: bool,
    keep_comments: bool,
    keep_fold: bool,
) {
    for node in nodes {
        match node {
            grammar::AST::Atom(v) => buffer.push_str(v),
            grammar::AST::QuotedPair(v) => {
                // TODO figure out the appropriate behavior with canonicalizing escaped printable
                // characters. quoted-pair can only be found inside comments (where '(' and ')'
                // must be escaped, inside quotes (where '"' and '\' must be escaped) and in
                // obs-dtext (where '\n' '\r' and '\s' '\t' must be escaped)
                //
                if *v == "\"" || *v == "\\" || *v == "(" || *v == ")" {
                    buffer.push_str("\\");
                }
                buffer.push_str(v);
            }
            grammar::AST::QuotedString(quoted) => {
                buffer.push_str("\"");
                write_to(buffer, &quoted, keep_whitespace, keep_comments, keep_fold);
                buffer.push_str("\"");
            }
            grammar::AST::WhiteSpace(v) if keep_whitespace => buffer.push_str(v),
            grammar::AST::Fold(v) if keep_fold => buffer.push_str(v),
            grammar::AST::Comment(comment) if keep_comments => {
                buffer.push_str("(");
                write_to(buffer, &comment, keep_whitespace, keep_comments, keep_fold);
                buffer.push_str(")");
            }
            _ => (),
        }
    }
}

pub fn is_rfc5322_email(s: &str) -> bool {
    // max length for rfc5622 is 63 bytes for local part, 255 bytes for domain part
    if s.len() > (63 + 1 + 255) {
        return false;
    }
    grammar::rfc5322::addr_spec(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::canonicalize_rfc5322_email;
    use super::grammar::rfc5322::addr_spec;
    use super::grammar::{AST};
    #[test]
    fn invalid_emails() {
        let invalid_emails = vec![
            // Missing @ sign and domain
            "plainaddress",
            // Garbage
            "#@%^%#$@#$@#.com",
            // Missing username
            "@domain.com",
            // Encoded html within email is invalid
            "Joe Smith <email@domain.com>",
            // Missing @
            "email.domain.com",
            // Two @ sign
            "email@domain@domain.com",
            // Leading dot in address is not allowed
            ".email@domain.com",
            // Trailing dot in address is not allowed
            "email.@domain.com",
            // Multiple dots
            "email..email@domain.com",
            // Unicode char as address
            "あいうえお@domain.com",
            // Multiple dot in the domain portion is invalid
            "email@domain..com",
        ];
        // TODO
        // Invalid IP format
        // "email@[111.222.333.44444]",
        for email in invalid_emails {
            println!("{}", email);
            assert!(addr_spec(email).is_err());
        }
    }

    #[test]
    fn ignore_comments() {
        let email = "e(comment)@localhost";
        println!("{:?}", addr_spec(email));
        assert_eq!(
            Ok("e@localhost".to_owned()),
            canonicalize_rfc5322_email(email)
        );
    }

    #[test]
    fn parse_comments() {
        let email = "e(comment)@localhost";
        let (local, domain) = addr_spec(email).unwrap();
        assert_eq!(
            vec![AST::Atom("e"), AST::Comment(vec![AST::Atom("comment")])],
            local
        );
        assert_eq!(vec![AST::Atom("localhost")], domain);
    }

    #[test]
    fn canonicalize_nested_comments() {
        let email = "e(comm\"quoted\"ent)@localhost";
        // Leading dash in front of domain is invalid domain but is allowed by RFC 5322
        // "email@-domain.com",
        println!("{:?}", addr_spec(email));
        assert_eq!(
            Ok("e@localhost".to_owned()),
            canonicalize_rfc5322_email(email)
        );
    }

    #[test]
    fn removes_trailing_whitespace() {
        // Text followed email is not allowed
        let email = "email@domain.com (Joe Smith)";
        println!("{:?}", addr_spec(email));
        assert_eq!(
            Ok("email@domain.com".to_owned()),
            canonicalize_rfc5322_email(email)
        );
    }

    #[test]
    fn domain_literals() {
        let email = "example@[127. \r\n 0.0.1]";
        println!("{:?}", addr_spec(email));
        assert_eq!(
            Ok("example@[127.0.0.1]".to_owned()),
            canonicalize_rfc5322_email(email)
        );
    }

    #[test]
    fn quoted_pair() {
        let email = "\"e\\\"ample\"@[127. \r\n 0.0.1]";
        println!("{:?}", addr_spec(email));
        assert_eq!(
            Ok(r#""e\"ample"@[127.0.0.1]"#.to_owned()),
            canonicalize_rfc5322_email(email)
        );
    }
}
