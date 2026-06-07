# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.0/filament-aarch64-apple-darwin.tar.gz"
      sha256 "358085d7797d5b3192e13e12b012f0bd9b8f03b7d78e5840ae599896f50c1674"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.0/filament-x86_64-apple-darwin.tar.gz"
      sha256 "a8b3c845fa1e9629a3dd40477d9dc259c011eaa4161ae34185589bd2ae70afdb"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.0/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "cab0da638804f3b7fee09197cfb1ba5fd89aa3269d863b4ade1fb7de34f5ce13"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
