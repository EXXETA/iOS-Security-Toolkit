Pod::Spec.new do |s|
  s.name             = 'SecurityToolkit'
  s.version          = '2.0.0'
  s.summary          = 'Simple and easy security threat detector in Swift'
  s.homepage         = 'https://github.com/EXXETA/iOS-Security-Toolkit'
  s.license          = { :type => 'MIT', :file => 'LICENSE.md' }
	s.author           = { 'Exxeta AG' => 'info@exxeta.com' }
  s.source           = { :git => 'https://github.com/EXXETA/iOS-Security-Toolkit.git', :tag => s.version }

  s.ios.deployment_target = '13.0'
	s.swift_version = '5'

  s.source_files = 'Sources/**/*'
	
end
