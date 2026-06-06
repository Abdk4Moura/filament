# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.1.0/filament-aarch64-apple-darwin.tar.gz"
      sha256 "872ac000b906456b14dd6a5ce0c219e2e9561e75c5649f148212f6d77f8e702f"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.1.0/filament-x86_64-apple-darwin.tar.gz"
      sha256 "235f51f157719408bea07888604fc37686b154e8933ce5f1d2e53b2196f33b9e"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.1.0/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "e5adb5e4f308f80af884587b9ca2e8c65f32ea3845a882ae1e02ad64cc4367be"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
