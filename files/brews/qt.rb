require 'formula'

class Qt < Formula
  homepage 'http://qt-project.org/'
  url 'http://download.qt-project.org/official_releases/qt/4.8/4.8.5/qt-everywhere-opensource-src-4.8.5.tar.gz'
  sha1 '745f9ebf091696c0d5403ce691dc28c039d77b9e'

  version "4.8.5-boxen2"

  head do
    url 'git://gitorious.org/qt/qt.git', :branch => '4.8'

    resource 'libWebKitSystemInterfaceMavericks' do
      url 'http://trac.webkit.org/export/157771/trunk/WebKitLibraries/libWebKitSystemInterfaceMavericks.a'
      sha1 'fc5ebf85f637f9da9a68692df350e441c8ef5d7e'
      version '157771'
    end if MacOS.version >= :mavericks
  end

  option :universal
  option 'with-qt3support', 'Build with deprecated Qt3Support module support'
  option 'with-docs', 'Build documentation'
  option 'developer', 'Build and link with developer options'

  # Newer (2013) machines seem to have issues compiling with SSSE3 optimizations
  option 'without-ssse3', 'Build without SSSE3 optimizations'

  depends_on "d-bus" => :optional
  depends_on "mysql" => :optional

  odie 'qt: --with-qtdbus has been renamed to --with-d-bus' if build.include? 'with-qtdbus'
  odie 'qt: --with-demos-examples is no longer supported' if build.include? 'with-demos-examples'
  odie 'qt: --with-debug-and-release is no longer supported' if build.include? 'with-debug-and-release'

  def patches
    # Patch to fix compilation on Mavericks (http://github.com/mxcl/homebrew/pull/23793)
    # Cam and should be safely removed once fixed upstream
    return unless MacOS.version >= :mavericks

    [
      # Change Ie9a72e3b: WIP: Compile on Mac OS 10.9 (https://codereview.qt-project.org/#change,69328)
      'https://gist.github.com/cliffrowley/f526019bb3182c237836/raw/459bfcfe340baa306eed81720b0734f4bede94d7/Ie9a72e3b.patch'
    ]
  end

  def install
    # Must be built with --HEAD on Mavericks at the moment
    raise 'Qt currently requires --HEAD on Mavericks' if MacOS.version == :mavericks and not build.head?

    ENV.universal_binary if build.universal?
    ENV.append "CXXFLAGS", "-fvisibility=hidden"

    args = ["-prefix", prefix,
            "-system-zlib",
            "-confirm-license", "-opensource",
            "-nomake", "demos", "-nomake", "examples",
            "-cocoa", "-fast", "-release"]

    # we have to disable these to avoid triggering optimization code
    # that will fail in superenv, perhaps because we rename clang to cc and
    # Qt thinks it can build with special assembler commands.
    # In --env=std, Qt seems aware of this.
    # But we want superenv, because it allows to build Qt in non-standard
    # locations and with Xcode-only.
    if superenv?
      args << '-no-3dnow'

      # disable SSSE3 if suppressed with --without-ssse3 or not supported bu the CPU or OS X version
      if build.without?('ssse3') || MacOS.version <= :snow_leopard || ! Hardware::CPU.ssse3?
        args << '-no-ssse3'
      end

      # Qt bug breaks compilation on newer (2013) Haswell based machines when SSSE3 optimizations are enabled
      # This can (and should) be safely removed once the bug is fixed upstream
      # https://bugreports.qt-project.org/browse/QTBUG-34499
      if Hardware::CPU.family == :haswell && MacOS.version >= :mavericks
        args << '-no-ssse3'
      end
    end

    args << "-L#{MacOS::X11.lib}" << "-I#{MacOS::X11.include}" if MacOS::X11.installed?

    args << "-platform" << "unsupported/macx-clang" if ENV.compiler == :clang

    args << "-plugin-sql-mysql" if build.with? 'mysql'

    if build.with? 'd-bus'
      dbus_opt = Formula.factory('d-bus').opt_prefix
      args << "-I#{dbus_opt}/lib/dbus-1.0/include"
      args << "-I#{dbus_opt}/include/dbus-1.0"
      args << "-L#{dbus_opt}/lib"
      args << "-ldbus-1"
    end

    if build.with? 'qt3support'
      args << "-qt3support"
    else
      args << "-no-qt3support"
    end

    unless build.with? 'docs'
      args << "-nomake" << "docs"
    end

    if MacOS.prefer_64_bit? or build.universal?
      args << '-arch' << 'x86_64'
    end

    if !MacOS.prefer_64_bit? or build.universal?
      args << '-arch' << 'x86'
    end

    args << '-developer-build' if build.include? 'developer'

    if MacOS.version >= :mavericks
      (buildpath/'src/3rdparty/webkit/WebKitLibraries').install resource('libWebKitSystemInterfaceMavericks')
    end

    system "./configure", *args

    begin
      system "make"
    rescue BuildError => e
      if MacOS.version >= :lion && Hardware::CPU.family == :haswell
        onoe <<-EOS.undent
          It appears you have a Haswell based CPU. It seems that Qt fails to build on some newer (2013) Haswell based machines.
          Try building again but adding --without-ssse3 to the end of the command line, and let us know if this worked for you.
        EOS
      end
      raise e
    end

    ENV.j1
    system "make install"

    # what are these anyway?
    (bin+'pixeltool.app').rmtree
    (bin+'qhelpconverter.app').rmtree
    # remove porting file for non-humans
    (prefix+'q3porting.xml').unlink if build.without? 'qt3support'

    # Some config scripts will only find Qt in a "Frameworks" folder
    frameworks.mkpath
    ln_s Dir["#{lib}/*.framework"], frameworks

    # The pkg-config files installed suggest that headers can be found in the
    # `include` directory. Make this so by creating symlinks from `include` to
    # the Frameworks' Headers folders.
    Pathname.glob(lib + '*.framework/Headers').each do |path|
      framework_name = File.basename(File.dirname(path), '.framework')
      ln_s path.realpath, include+framework_name
    end

    Pathname.glob(bin + '*.app').each do |path|
      mv path, prefix
    end
  end

  test do
    system "#{bin}/qmake", '-project'
  end

  def caveats; <<-EOS.undent
    We agreed to the Qt opensource license for you.
    If this is unacceptable you should uninstall.
    EOS
  end
end
