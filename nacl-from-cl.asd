(asdf:defsystem "nacl-from-cl"
		:depends-on ("cffi")
		:components ((:file "package")
			     (:file "main")))
