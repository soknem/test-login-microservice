import Image from "next/image";
import Link from "next/link";

export default function Home() {
  return (
      <>
        <h1 className="text-[3rem]">Welcome to Yelp</h1>
        <Link href="/oauth2/authorization/nextjs" className="bg-blue-300 text-black m-5 w-[300px] h-[80px] flex justify-center items-center rounded-sm hover:scale-105 transition-transform duration-200 text-[2rem] border border-blue-400  hover:bg-blue-400 hover:border-blue-500">
        Login
        </Link>
      </>
  );
}