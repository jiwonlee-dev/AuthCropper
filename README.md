# AuthCropper
As surveillance systems are popular, the privacy of the recorded video becomes more important. On the other hand, the authenticity of video images should be guaranteed when used as evidence in court. It is challenging to satisfy both (personal) privacy and authenticity of a video simultaneously, since the privacy requires modifications (e.g.,partial deletions) of an original video image while the authenticity does not allow any modifications of the original image. This project proposes a novel method to convert an encryption scheme to support partial decryption with a constant number of keys and construct a privacy-aware authentication scheme by combining with a signature scheme.

Currently, this project will show a cropped image with a single image file acquired.

![AuthCropper Example](images/AuthCropperExample.PNG)

## Getting Started

These instructions will get you a copy of the project up and running in your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

* [OpenCV](https://docs.opencv.org/4.1.2/d7/d9f/tutorial_linux_install.html)

* [OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL)

* [PBC Library](https://crypto.stanford.edu/pbc/download.html)

  The PBC library needs [the GMP library](https://gmplib.org/).

  This build system has been tested and works on Linux and Mac OS X with a fink installation.

	```
	$ ./configure
	$ make
	$ make install
	```

	On Windows, the configure command requires a couple of options:

	```
	$ ./configure -disable-static -enable-shared
	```

	By default the library is installed in `/usr/local/lib`. On some systems, this may not be in the library path. One way to fix this is to edit `/etc/ld.so.conf` and run `ldconfig`.

### Installing

1. Clone or [download](https://github.com/snp-lab/AuthCropper/archive/master.zip) the project
2. If the project is in a zip, unzip it.

## Deployment

1. Add an image in **src** folder

   ![image Example](images/dog.jpg)

2. Open **main.cpp** and set an image name

   1. Set an image name
      ```
      src = imread("yourimage.jpg", cv::ImreadModes::IMREAD_GRAYSCALE);
      ```
   2. Set an encrypted image name
      ```
      imwrite("enc_yourimage.jpg", dst);
      ```
   3. Set a decrypted image name

      ```
      imwrite("dec_yourimage.jpeg", Dec);
      ```

3. Run

   1. Verify the signature

      First the signature (any applied signature) should be verified for the input image.

   2.  Type a decryption block range

      ![input Example](images/inputExample.PNG)

   3.  Both Encrypted and Decrypted images are generated

      ![Enc Example](images/enc_dog.jpg)

      ![Dec Example](images/Dec_dog.jpeg)

   

