<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

class AuthenticatedSessionController extends Controller
{
    /**
     * @group Authentication
     * 
     * Login User
     */
    public function store(LoginRequest $request): Response
    {
        dd('king');
        $request->authenticate();

        $request->session()->regenerate();

        return response()->noContent();
    }

    /**
     * @group Authentication
     * 
     * Logout User
     */
    public function destroy(Request $request): Response
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return response()->noContent();
    }
}
