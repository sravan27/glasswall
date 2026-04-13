from pathlib import Path
import textwrap

from glasswall.parsers import parse_dependencies


def test_parse_multiple_manifest_types(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()

    (project / "requirements.txt").write_text(
        """
        requests==2.28.1
        urllib3==1.26.12
        """.strip()
    )

    (project / "package-lock.json").write_text(
        """
        {
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo" },
            "node_modules/lodash": { "version": "4.17.20" },
            "node_modules/ansi-regex": { "version": "5.0.0" }
          }
        }
        """.strip()
    )

    (project / "Cargo.lock").write_text(
        """
        version = 3

        [[package]]
        name = "serde"
        version = "1.0.210"
        """.strip()
    )

    dependencies = parse_dependencies(project)

    keys = {(dependency.ecosystem, dependency.name, dependency.version) for dependency in dependencies}
    assert ("PyPI", "requests", "2.28.1") in keys
    assert ("PyPI", "urllib3", "1.26.12") in keys
    assert ("npm", "lodash", "4.17.20") in keys
    assert ("npm", "ansi-regex", "5.0.0") in keys
    assert ("crates.io", "serde", "1.0.210") in keys


def test_parse_go_sum_deduplicates_go_mod_entries(tmp_path: Path) -> None:
    project = tmp_path / "go-repo"
    project.mkdir()

    (project / "go.sum").write_text(
        """
        github.com/pkg/errors v0.9.1 h1:test
        github.com/pkg/errors v0.9.1/go.mod h1:test
        """.strip()
    )

    dependencies = parse_dependencies(project)

    assert len(dependencies) == 1
    assert dependencies[0].name == "github.com/pkg/errors"
    assert dependencies[0].version == "v0.9.1"


def test_parse_additional_lockfiles(tmp_path: Path) -> None:
    project = tmp_path / "polyglot"
    project.mkdir()

    (project / "uv.lock").write_text(
        """
        version = 1

        [[package]]
        name = "fastapi"
        version = "0.115.0"
        """.strip()
    )
    (project / "pnpm-lock.yaml").write_text(
        textwrap.dedent(
            """
            lockfileVersion: '9.0'
            packages:
              lodash@4.17.21:
                resolution: {integrity: sha512-test}
              '@scope/pkg@1.2.3':
                resolution: {integrity: sha512-test}
            """
        ).strip()
    )
    (project / "Gemfile.lock").write_text(
        textwrap.dedent(
            """
            GEM
              specs:
                rack (3.1.7)
                zeitwerk (2.6.18)
            """
        ).strip()
    )
    (project / "composer.lock").write_text(
        """
        {
          "packages": [
            {"name": "symfony/http-foundation", "version": "v7.1.3"}
          ]
        }
        """.strip()
    )

    dependencies = parse_dependencies(project)
    keys = {(dependency.ecosystem, dependency.name, dependency.version) for dependency in dependencies}

    assert ("PyPI", "fastapi", "0.115.0") in keys
    assert ("npm", "lodash", "4.17.21") in keys
    assert ("npm", "@scope/pkg", "1.2.3") in keys
    assert ("RubyGems", "rack", "3.1.7") in keys
    assert ("Packagist", "symfony/http-foundation", "7.1.3") in keys
