(in-package :nacl-from-cl)

(define-foreign-library libnacl
  (t (:default "libnacl")))

(use-foreign-library libnacl)
(declaim (optimize (speed 0) (debug 3) (safety 3)))

(defconstant SECRETKEYBYTES 64)
(defconstant PUBLICKEYBYTES 32)
(defconstant BYTES 64)

;; int crypto_sign_keypair(unsigned char *pk,unsigned char *sk)
(defcfun ("crypto_sign_edwards25519sha512batch_ref_keypair"
	  c-crypto-keypair)
    :int
  (pk (:pointer :unsigned-char))
  (sk (:pointer :unsigned-char)))

(defun crypto-keypair ()
  (let ((sk (make-shareable-byte-vector SECRETKEYBYTES))
	(pk (make-shareable-byte-vector PUBLICKEYBYTES)))
    (with-pointer-to-vector-data
     (psk sk)
     (with-pointer-to-vector-data
      (ppk pk)
       (when (not (= (c-crypto-keypair ppk psk) 0))
	(error "Error when creating the keypair"))
      (values sk pk)))))

;; int crypto_sign(unsigned char *sm,unsigned long long *smlen,const unsigned char *m,unsigned long long mlen,const unsigned char *sk)
(defcfun ("crypto_sign_edwards25519sha512batch_ref"
	  c-crypto-sign)
    :int
  (sm (:pointer :unsigned-char))
  (smlen (:pointer :unsigned-long-long))
  (m (:pointer :unsigned-char))
  (mlen :unsigned-long-long)
  (sk (:pointer :unsigned-char)))

;; int crypto_sign_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
(defcfun ("crypto_sign_edwards25519sha512batch_ref_open"
	  c-crypto-sign-open)
    :int
  (m (:pointer :unsigned-char))
  (mlen (:pointer :unsigned-long-long))
  (sm (:pointer :unsigned-char))
  (smlen :unsigned-long-long)
  (pk (:pointer :unsigned-char)))

(defun crypto-sign (m sk)
  (declare (type (array (unsigned-byte 8) *) m sk))
  (let ((sm (make-shareable-byte-vector (+ (length m) BYTES))))
    (with-pointer-to-vector-data
     (psk sk)
     (with-pointer-to-vector-data
      (pm m)
      (with-pointer-to-vector-data
       (psm sm)
       (with-foreign-object
	(csmlen :int)
	 (when (not (= (c-crypto-sign psm csmlen pm (length m) psk) 0))
	  (error "Error during signature"))
	(subseq sm 0 (mem-aref csmlen :int))))))))


(defun crypto-sign-open (sm pk)
  (declare (type (array (unsigned-byte 8) *) sm pk))
  (let ((m (make-shareable-byte-vector (length sm))))
    (with-pointer-to-vector-data
     (ppk pk)
     (with-pointer-to-vector-data
      (pm m)
      (with-pointer-to-vector-data
       (psm sm)
       (with-foreign-object
	(cmlen :int)
	 (when (not (= (c-crypto-sign-open pm cmlen psm (length sm) ppk) 0))
	  (error "Error during signature open"))
	(subseq m 0 (mem-aref cmlen :int))))))))


(defun main ()
  (let ((m (make-array 9 :element-type '(unsigned-byte 8)
		       :initial-contents '(1 2 3 4 5 6 7 8 9))))
    (multiple-value-bind (sk pk) (crypto-keypair)
			 (let* ((sm (crypto-sign m sk))
				(newm (crypto-sign-open sm pk)))
			   (print m)
			   (print sm)
			   (print newm)))))

(main)

