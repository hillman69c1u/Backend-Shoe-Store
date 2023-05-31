<?php

namespace App\Http\Controllers\API;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{

    /**
     * @param Request $request
     * @return mixed
     */
    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(),'Data profile user berhasil diambil');
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     * @throws \Exception
     */
    public function login(Request $request)
    {
        try {
            $login = $request->username;
            if ($request->email) {
                $validate['email'] = 'email|required';
                $login = $request->email;
            } else {
                $validate['username'] = 'required';
            }

            $validate['password'] = 'required';
            $validator = Validator::make($request->all(), $validate);
            if ($validator->fails()) {
                return ResponseFormatter::error([
                    'message' => 'Something went wrong',
                    'error' => implode(" ", $validator->errors()->all()),
                ],'Authentication Failed', 500);
            }

            $fieldType = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

            $credentials = request([$fieldType, 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ],'Authentication Failed', 500);
            }

            $user = User::where($fieldType, $login)->first();
            if ( ! Hash::check($request->password, $user->password, [])) {
                throw new Exception('Invalid Credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ],'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error,
            ],'Authentication Failed', 500);
        }
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     * @throws \Exception
     */
    public function register(Request $request)
    {
        try {
            $validate = [
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'password' => ['required', 'string', new Password]
            ];
            $validator = Validator::make($request->all(), $validate);
            if ($validator->fails()) {
                return ResponseFormatter::error([
                    'message' => 'Something went wrong',
                    'error' => implode(" ", $validator->errors()->all()),
                ],'Authentication Failed', 500);
            }

            User::create([
                'name' => $request->name,
                'email' => $request->email,
                'username' => $request->username,
                'password' => Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ],'User Registered');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error,
            ],'Authentication Failed', 500);
        }
    }

    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();

        return ResponseFormatter::success($token,'Token Revoked');
    }

    public function updateProfile(Request $request)
    {
        try {
            $user = User::find(Auth::id());
            $data = $request->all();

            $validate['name'] = ['required', 'string', 'max:255'];
            if ($user->username != $request->username) {
                $validate['username'] = ['required', 'string', 'max:255', 'unique:users'];
            }
            if ($user->email != $request->email) {
                $validate['email'] = ['required', 'string', 'email', 'max:255', 'unique:users'];
            }
            if ($request->password) {
                $validate['password'] =  ['required', 'string', new Password];
                $data['password'] = Hash::make($data['password']);
            }
            $validator = Validator::make($request->all(), $validate);
            if ($validator->fails()) {
                return ResponseFormatter::error([
                    'message' => 'Something went wrong',
                    'error' => implode(" ", $validator->errors()->all()),
                ],'Authentication Failed', 500);
            }
    
            $user->update($data);
    
            return ResponseFormatter::success($user,'Profile Updated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error,
            ],'Authentication Failed', 500);
        }
    }
}
