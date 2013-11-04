# Installs Qt via Homebrew.
#
# Usage:
#
#     include qt

class qt {
  include homebrew
  include xquartz

  homebrew::formula { 'qt':
    before => Package['boxen/brews/qt'],
  }

  case $::macosx_productversion_major {
    '10.9': {

      package { 'boxen/brews/qt':
        ensure          => 'HEAD',
        require         => Class['xquartz'],
        install_options => ['--HEAD']
      }

      package { 'boxen/brews/qt_mavericks':
        ensure          => absent
      }
    }

    default: {
      package { 'boxen/brews/qt':
        ensure  => '4.8.5-boxen2',
        require => Class['xquartz'],
      }
    }
  }
}
