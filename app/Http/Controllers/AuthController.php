<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $req)
    {
        $user = User::where('email', $req->email)->first();
        if (! $user || ! Hash::check($req->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }
        $token = $user->createToken('api-token')->plainTextToken;
        return response()->json(['token' => $token]);
    }

    public function logout(Request $req)
    {
        if ($req->user() && $req->user()->currentAccessToken()) {
            $req->user()->currentAccessToken()->delete();
        }
        return response()->json(['message' => 'logged out']);
    }
}
