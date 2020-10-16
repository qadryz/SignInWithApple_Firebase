//
//  Code.swift
//  
//
//  Created by Joel Joseph on 10/15/20.
//

import SwiftUI
import CryptoKit
import FirebaseAuth
import AuthenticationServices

struct Code: View {
    
    //Variable to keep track of nonce
    @State var currentNonce:String?
    
    //Hashing function requires Cryptokit
    func sha256(_ input: String) -> String {
        let inputData = Data(input.utf8)
        let hashedData = SHA256.hash(data: inputData)
        let hashString = hashedData.compactMap {
        return String(format: "%02x", $0)
        }.joined()

        return hashString
    }
    
    //Creates a random string of characters
    func randomNonceString(length: Int = 32) -> String {
        precondition(length > 0)
        let charset: Array<Character> =
        Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
        var result = ""
        var remainingLength = length

        while remainingLength > 0 {
            let randoms: [UInt8] = (0 ..< 16).map { _ in
                var random: UInt8 = 0
                let errorCode = SecRandomCopyBytes(kSecRandomDefault, 1, &random)
                if errorCode != errSecSuccess {
                    fatalError("Unable to generate nonce. SecRandomCopyBytes failed with OSStatus \(errorCode)")
                }
                return random
            }

            randoms.forEach { random in
                if length == 0 {
                    return
                }

                if random < charset.count {
                    result.append(charset[Int(random)])
                    remainingLength -= 1
                }
            }
        }

        return result
    }
    var body: some View {
        VStack {
            
            //Print current userID from Firebase
            Button(action:{print("Current UserID: \(String(describing: Auth.auth().currentUser?.uid))")}){
                Text("Print Current User")
            }.frame(width: SCREEN_WIDTH/1.5, height: 50, alignment: .center)
            
            //Sign out of Firebase Button
            Button(action:{print("Signed Out"); do{try Auth.auth().signOut()}catch{ print("Err")}}){
                Text("Sign Out")
            }.frame(width: SCREEN_WIDTH/1.5, height: 50, alignment: .center)
            
            //Sign in with Apple button
            SignInWithAppleButton(
                
                //Request
                onRequest: { request in
                    let nonce = randomNonceString()
                    currentNonce = nonce
                    request.requestedScopes = [.fullName, .email]
                    request.nonce = sha256(nonce)
                },
                
                //Completion
                onCompletion: { result in
                    switch result {
                        case .success(let authResults):
                            switch authResults.credential {
                                case let appleIDCredential as ASAuthorizationAppleIDCredential:
                                
                                        guard let nonce = currentNonce else {
                                          fatalError("Invalid state: A login callback was received, but no login request was sent.")
                                        }
                                        guard let appleIDToken = appleIDCredential.identityToken else {
                                            fatalError("Invalid state: A login callback was received, but no login request was sent.")
                                        }
                                        guard let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
                                          print("Unable to serialize token string from data: \(appleIDToken.debugDescription)")
                                          return
                                        }
                                        
                                        //Creating a request for firebase
                                        let credential = OAuthProvider.credential(withProviderID: "apple.com",idToken: idTokenString,rawNonce: nonce)
                                
                                        //Sending Request to Firebase
                                        Auth.auth().signIn(with: credential) { (authResult, error) in
                                            if (error != nil) {
                                                // Error. If error.code == .MissingOrInvalidNonce, make sure
                                                // you're sending the SHA256-hashed nonce as a hex string with
                                                // your request to Apple.
                                                print(error?.localizedDescription as Any)
                                                return
                                            }
                                            // User is signed in to Firebase with Apple.
                                            print("you're in")
                                        }
                                
                                    //Prints the current userID for firebase
                                    print("\(String(describing: Auth.auth().currentUser?.uid))")
                            default:
                                break
                                        
                                    }
                           default:
                                break
                        }
                    
                }
            ).frame(width: SCREEN_WIDTH/1.5, height: 50, alignment: .center)
        }
    }
}

struct Code_Previews: PreviewProvider {
    static var previews: some View {
        Code()
    }
}
