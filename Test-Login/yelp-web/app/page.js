import Image from "next/image";
import Link from "next/link";

export default function Home() {
    return (
        <>
            <h1 className="text-[3rem] text-center">Welcome to Yelp</h1>

            <div className="flex flex-col items-center mt-10">
                {/* Login with Next.js */}
                <Link
                    href="/oauth2/authorization/nextjs"
                    className="bg-blue-300 text-black m-5 w-[300px] h-[80px] flex justify-center items-center rounded-sm hover:scale-105 transition-transform duration-200 text-[2rem] border border-blue-400 hover:bg-blue-400 hover:border-blue-500"
                >
                    Login with Next.js
                </Link>

                {/* Login with GitHub */}
                <Link
                    href="/oauth2/authorization/github"
                    className="bg-gray-700 text-white m-5 w-[300px] h-[80px] flex justify-center items-center rounded-sm hover:scale-105 transition-transform duration-200 text-[2rem] border border-gray-800 hover:bg-gray-800 hover:border-gray-900"
                >
                    Login with GitHub
                </Link>

                {/* Login with Telegram */}
                <Link
                    href="/oauth2/authorization/telegram"
                    className="bg-blue-500 text-white m-5 w-[300px] h-[80px] flex justify-center items-center rounded-sm hover:scale-105 transition-transform duration-200 text-[2rem] border border-blue-600 hover:bg-blue-600 hover:border-blue-700"
                >
                    Login with Telegram
                </Link>

                {/* Login with Google */}
                <Link
                    href="/oauth2/authorization/google"
                    className="bg-red-500 text-white m-5 w-[300px] h-[80px] flex justify-center items-center rounded-sm hover:scale-105 transition-transform duration-200 text-[2rem] border border-red-600 hover:bg-red-600 hover:border-red-700"
                >
                    Login with Google
                </Link>
            </div>
        </>
    );
}
