# Installs Qt via Homebrew.
#
# Usage:
#
#     include qt

class qt {
  include homebrew
  include xquartz

  case $::macosx_productversion_major {
    '10.9': {
      homebrew::formula { 'qt_mavericks':
        before => Package['boxen/brews/qt_mavericks'],
      }

      package { 'boxen/brews/qt_mavericks':
        ensure          => 'HEAD',
        require         => Class['xquartz'],
        install_options => ['--HEAD']
      }
    }

    default: {
      homebrew::formula { 'qt':
        before => Package['boxen/brews/qt'],
      }

      package { 'boxen/brews/qt':
        ensure  => '4.8.5-boxen1',
        require => Class['xquartz'],
      }
    }
  }
}
